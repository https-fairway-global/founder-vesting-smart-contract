use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Finite, Interval}
// Import Interval for ValidityRange
use aiken/option
use cardano/address.{Address, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value, quantity_of}
use cardano/transaction.{DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, ScriptPurpose, Transaction}

// --- Datum and Redeemer Definitions for Linear Vesting ---
pub type VestingDatum {
  owner: VerificationKeyHash,
  beneficiary: VerificationKeyHash,
  start_time: Int,
  // Vesting start time (POSIX milliseconds)
  cliff_date: Int,
  // Cliff time (POSIX milliseconds)
  end_date: Int,
  // Vesting end time (POSIX milliseconds)
  total_vesting_quantity: Int,
  claimed_quantity: Int,
}

// Amount already claimed

pub type Redeemer {
  Claim { amount_to_claim: Int }
  // Specify amount to claim
  Refund
}

// Owner reclaims funds

// --- Validator ---
validator vesting(
  master_token_policy: PolicyId,
  master_token_name: AssetName,
) {
  spend(datum_opt: Option<VestingDatum>, redeemer: Redeemer, own_ref: OutputReference, self: Transaction) {
    // Unwrap the optional datum first.
    expect Some(datum) = datum_opt

    // No need to cast redeemer when it's passed directly
    when redeemer is {
      Refund ->
        handle_refund(
          datum,
          own_ref, // Pass own_ref
          self, // Pass self (Transaction)
          master_token_policy,
          master_token_name,
        )
      Claim { amount_to_claim } ->
        handle_claim(
          datum,
          amount_to_claim,
          own_ref, // Pass own_ref
          self, // Pass self (Transaction)
          master_token_policy,
          master_token_name,
        )
    }
  }

  // Fallback handler (good practice)
  else(_purpose: ScriptPurpose) { // ScriptPurpose still needed here
    fail @"Invalid script purpose"
  }
}

// --- Action Handlers & Helpers ---

// Calculate the total amount vested at a given time
fn calculate_vested_amount(datum: VestingDatum, current_time: Int) -> Int {
  // Use Int for time
  // Before cliff, nothing is vested
  if current_time < datum.cliff_date {
    0
  } else if current_time >= datum.end_date {
    // After end date, everything is vested
    datum.total_vesting_quantity
  } else {
    // Between cliff and end date, calculate linear vesting
    let total_duration = datum.end_date - datum.start_time
    let time_elapsed = current_time - datum.start_time
    if total_duration > 0 {
      datum.total_vesting_quantity * time_elapsed / total_duration
    } else {
      if current_time >= datum.start_time {
        datum.total_vesting_quantity
      } else {
        0
      }
    }
  }
}

// Find the specific input UTxO being spent by this validator instance
// Now takes Transaction and the OutputReference directly
fn find_own_input(tx: Transaction, own_ref: OutputReference) -> Option<Input> {
  list.find(tx.inputs, fn(input) { input.output_reference == own_ref })
}

// Find the output that continues the contract state (pays back to the script)
// Needs Transaction and OutputReference to find the input address
fn find_continuing_output(tx: Transaction, own_ref: OutputReference) -> Option<Output> {
  when find_own_input(tx, own_ref) is {
    Some(own_input) -> {
      let script_address = own_input.output.address
      list.find(tx.outputs, fn(output) { output.address == script_address })
    }
    None -> None
  }
}

// Helper to sum the quantity of a specific asset sent to a target address
fn sum_sent_to(
  tx: Transaction,
  target_address: Address,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Int {
  list.foldr(
    tx.outputs,
    0,
    fn(output, current_sum) {
      if output.address == target_address {
        current_sum + quantity_of(output.value, policy_id, asset_name)
      } else {
        current_sum
      }
    },
  )
}

// Handler for beneficiary claiming funds
// Needs own_ref and self (Transaction)
fn handle_claim(
  datum: VestingDatum,
  amount_to_claim: Int,
  own_ref: OutputReference, // Add own_ref
  self: Transaction, // Change context to self
  master_token_policy: PolicyId,
  master_token_name: AssetName,
) -> Bool {
  // Get the lower bound (POSIX milliseconds) from the validity range
  let current_time: Int =
    when self.validity_range.lower_bound.bound_type is {
      Finite(t) -> t
      _ -> fail
    }

  // --- Basic Checks ---
  expect amount_to_claim > 0
  expect list.has(self.extra_signatories, datum.beneficiary)
  expect current_time >= datum.cliff_date

  // --- Calculate Withdrawable Amount ---
  let total_vested_now = calculate_vested_amount(datum, current_time)
  let max_withdrawable_now = total_vested_now - datum.claimed_quantity
  expect amount_to_claim <= max_withdrawable_now

  // --- Validate Input ---
  expect Some(own_input) = find_own_input(self, own_ref) // Pass self and own_ref

  // --- Validate Outputs ---
  // Payment to beneficiary
  let beneficiary_address = Address(VerificationKey(datum.beneficiary), None)
  let paid_to_beneficiary =
    sum_sent_to(self, beneficiary_address, master_token_policy, master_token_name) // Pass self
  expect paid_to_beneficiary >= amount_to_claim

  // State continuation
  expect Some(continuing_output) = find_continuing_output(self, own_ref) // Pass self and own_ref

  // Remaining token quantity check
  let input_value = own_input.output.value
  let input_token_quantity =
    quantity_of(input_value, master_token_policy, master_token_name)
  let expected_remaining_quantity = input_token_quantity - amount_to_claim
  let output_token_quantity =
    quantity_of(
      continuing_output.value,
      master_token_policy,
      master_token_name,
    )
  expect output_token_quantity >= expected_remaining_quantity

  // Updated datum check
  let output_datum: VestingDatum =
    when continuing_output.datum is {
      InlineDatum(generic_data) -> {
        expect casted_datum: VestingDatum = generic_data
        casted_datum
      }
      DatumHash(_) -> fail @"Expected inline datum, found hash"
      NoDatum -> fail @"Expected inline datum, found none"
    }
  expect output_datum.owner == datum.owner
  expect output_datum.beneficiary == datum.beneficiary
  expect output_datum.start_time == datum.start_time
  expect output_datum.cliff_date == datum.cliff_date
  expect output_datum.end_date == datum.end_date
  expect output_datum.total_vesting_quantity == datum.total_vesting_quantity
  expect
    output_datum.claimed_quantity == datum.claimed_quantity + amount_to_claim

  True
}

// Handler for owner refunding funds
// Needs own_ref and self (Transaction)
fn handle_refund(
  datum: VestingDatum,
  own_ref: OutputReference, // Add own_ref
  self: Transaction, // Change context to self
  master_token_policy: PolicyId,
  master_token_name: AssetName,
) -> Bool {
  let current_time: Int =
    when self.validity_range.lower_bound.bound_type is {
      Finite(t) -> t
      _ -> fail
    }

  expect list.has(self.extra_signatories, datum.owner)
  expect current_time < datum.start_time

  expect Some(own_input) = find_own_input(self, own_ref) // Pass self and own_ref
  let input_token_quantity =
    quantity_of(own_input.output.value, master_token_policy, master_token_name)
  let expected_refund_amount =
    datum.total_vesting_quantity - datum.claimed_quantity
  expect input_token_quantity == expected_refund_amount

  let owner_address = Address(VerificationKey(datum.owner), None)
  let paid_to_owner =
    sum_sent_to(self, owner_address, master_token_policy, master_token_name) // Pass self
  expect paid_to_owner >= expected_refund_amount

  True
}
