use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Finite, Interval}
// Import Interval for ValidityRange
use cardano/address.{Address, VerificationKey}
use cardano/assets.{AssetName, PolicyId, quantity_of}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, ScriptPurpose,
  Transaction,
}

// --- Datum and Redeemer Definitions for Linear Vesting ---

/// Datum stored with each vesting UTxO.
/// Defines the vesting schedule, beneficiary, owner, and current state.
pub type VestingDatum {
  /// Verification key hash of the wallet that initially locked the funds.
  /// Allowed to refund before vesting starts.
  owner: VerificationKeyHash,
  /// Verification key hash of the wallet entitled to claim vested funds.
  beneficiary: VerificationKeyHash,
  /// The POSIX time (ms) when the vesting period begins.
  start_time: Int,
  /// The POSIX time (ms) after which the beneficiary can start claiming.
  /// Before this time, no funds are vested.
  cliff_date: Int,
  /// The POSIX time (ms) when all funds become fully vested.
  end_date: Int,
  /// The total amount of the master token locked in the vesting contract.
  total_vesting_quantity: Int,
  /// The amount of the master token already claimed by the beneficiary.
  claimed_quantity: Int,
}

/// Redeemer defining the action being performed on the vesting contract.
pub type Redeemer {
  /// Action for the beneficiary to claim vested tokens.
  Claim {
    /// The specific amount the beneficiary intends to claim in this transaction.
    amount_to_claim: Int,
  }
  /// Action for the owner to reclaim all remaining tokens before the vesting period starts.
  Refund
}

// --- Validator ---

/// Main validator for the linear vesting contract.
/// Controls spending of UTxOs locked at the script address.
/// Parameters are embedded into the script at compile/blueprint application time.
validator vesting(
  /// Policy ID of the token being vested.
  master_token_policy: PolicyId,
  /// Asset Name of the token being vested.
  master_token_name: AssetName,
) {
  /// Spend handler: Controls how UTxOs locked by this validator can be spent.
  spend(
    /// The datum attached to the UTxO being spent (passed as Option).
    datum_opt: Option<VestingDatum>,
    /// The action (Claim, Refund) being attempted.
    redeemer: Redeemer,
    /// The specific UTxO being spent.
    own_ref: OutputReference,
    /// The full transaction context provided by the ledger.
    self: Transaction,
  ) {
    // Ensure the datum is present, otherwise fail.
    expect Some(datum) = datum_opt

    // Dispatch to the appropriate handler based on the redeemer action.
    when redeemer is {
      Refund ->
        handle_refund(
          datum,
          own_ref,
          self,
          master_token_policy,
          master_token_name,
        )
      Claim { amount_to_claim } ->
        handle_claim(
          datum,
          amount_to_claim,
          own_ref,
          self,
          master_token_policy,
          master_token_name,
        )
    }
  }

  // Fallback handler to reject any script purpose other than 'spend'.
  else(_purpose: ScriptPurpose) {
    fail @"Invalid script purpose"
  }
}

// --- Action Handlers & Helpers ---

/// Calculate the total amount vested at a given time based on linear interpolation.
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
    // Prevent division by zero if start and end are the same
    if total_duration > 0 {
      // Linear interpolation: (Total Amount * Time Elapsed) / Total Duration
      datum.total_vesting_quantity * time_elapsed / total_duration
    } else {
      // If duration is zero or negative, vest all if past start time
      if current_time >= datum.start_time {
        datum.total_vesting_quantity
      } else {
        0
      }
    }
  }
}

/// Find the specific input UTxO being spent by this validator instance.
fn find_own_input(tx: Transaction, own_ref: OutputReference) -> Option<Input> {
  list.find(tx.inputs, fn(input) { input.output_reference == own_ref })
}

/// Find the output that continues the contract state (pays back to the script address).
fn find_continuing_output(
  tx: Transaction,
  own_ref: OutputReference,
) -> Option<Output> {
  // First find the input being spent to determine the script's address
  when find_own_input(tx, own_ref) is {
    Some(own_input) -> {
      let script_address = own_input.output.address
      // Then find an output going back to that same address
      list.find(tx.outputs, fn(output) { output.address == script_address })
    }
    // If the input couldn't be found, something is wrong
    None -> None
  }
}

/// Helper to sum the quantity of a specific asset sent to a target address within the transaction outputs.
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

/// Handler for validating a beneficiary's claim action.
fn handle_claim(
  datum: VestingDatum,
  amount_to_claim: Int,
  own_ref: OutputReference,
  self: Transaction,
  master_token_policy: PolicyId,
  master_token_name: AssetName,
) -> Bool {
  // Determine current time from transaction validity lower bound.
  let current_time: Int =
    when self.validity_range.lower_bound.bound_type is {
      Finite(t) -> t
      // Must have a finite lower bound
      _ -> fail
    }

  // --- Basic Claim Rule Checks ---
  // 1. Claim amount must be positive.
  expect amount_to_claim > 0
  // 2. Transaction must be signed by the beneficiary.
  expect list.has(self.extra_signatories, datum.beneficiary)
  // 3. Claim can only happen after the cliff date.
  expect current_time >= datum.cliff_date

  // --- Calculate Withdrawable Amount ---
  // Calculate total vested based on current time.
  let total_vested_now = calculate_vested_amount(datum, current_time)
  // Calculate how much is actually available to withdraw now.
  let max_withdrawable_now = total_vested_now - datum.claimed_quantity
  // 4. Cannot claim more than the currently withdrawable amount.
  expect amount_to_claim <= max_withdrawable_now

  // --- Validate Input UTxO ---
  expect Some(own_input) = find_own_input(self, own_ref)

  // --- Validate Output Payments & State Continuation ---
  // 5. Ensure the beneficiary is paid at least the claimed amount.
  let beneficiary_address = Address(VerificationKey(datum.beneficiary), None)
  let paid_to_beneficiary =
    sum_sent_to(
      self,
      beneficiary_address,
      master_token_policy,
      master_token_name,
    )
  expect paid_to_beneficiary >= amount_to_claim

  // 6. Ensure the script UTxO is continued correctly.
  expect Some(continuing_output) = find_continuing_output(self, own_ref)

  // 7. Ensure the correct remaining token quantity is sent back to the script.
  let input_value = own_input.output.value
  let input_token_quantity =
    quantity_of(input_value, master_token_policy, master_token_name)
  let expected_remaining_quantity = input_token_quantity - amount_to_claim
  let output_token_quantity =
    quantity_of(continuing_output.value, master_token_policy, master_token_name)
  // Use >= to allow for potential fees paid from the script UTxO if needed, though typically handled by collateral.
  expect output_token_quantity >= expected_remaining_quantity

  // 8. Ensure the datum in the continuing output is correctly updated.
  let output_datum: VestingDatum =
    when continuing_output.datum is {
      InlineDatum(generic_data) -> {
        expect casted_datum: VestingDatum = generic_data
        casted_datum
      }
      DatumHash(_) -> fail @"Expected inline datum, found hash"
      NoDatum -> fail @"Expected inline datum, found none"
    }
  // Check immutable fields.
  expect output_datum.owner == datum.owner
  expect output_datum.beneficiary == datum.beneficiary
  expect output_datum.start_time == datum.start_time
  expect output_datum.cliff_date == datum.cliff_date
  expect output_datum.end_date == datum.end_date
  expect output_datum.total_vesting_quantity == datum.total_vesting_quantity
  // Check updated claimed quantity.
  expect
    output_datum.claimed_quantity == datum.claimed_quantity + amount_to_claim

  // All checks passed.
  True
}

/// Handler for validating an owner's refund action.
fn handle_refund(
  datum: VestingDatum,
  own_ref: OutputReference,
  self: Transaction,
  master_token_policy: PolicyId,
  master_token_name: AssetName,
) -> Bool {
  // Determine current time from transaction validity lower bound.
  let current_time: Int =
    when self.validity_range.lower_bound.bound_type is {
      Finite(t) -> t
      // Must have a finite lower bound
      _ -> fail
    }

  // --- Basic Refund Rule Checks ---
  // 1. Transaction must be signed by the owner.
  expect list.has(self.extra_signatories, datum.owner)
  // 2. Refund can only happen before the vesting period starts.
  expect current_time < datum.start_time

  // --- Validate Input & Payment ---
  // Ensure the input UTxO being spent is found.
  // Use 'expect' here as it's pattern matching on Option
  expect Some(own_input) = find_own_input(self, own_ref)
  // Calculate the total amount that should be in the UTxO (total locked - already claimed).
  let input_token_quantity =
    quantity_of(own_input.output.value, master_token_policy, master_token_name)
  let expected_refund_amount =
    datum.total_vesting_quantity - datum.claimed_quantity
  // 3. Ensure the input contains exactly the expected amount to be refunded.
  expect input_token_quantity == expected_refund_amount

  // 4. Ensure the owner is paid back the full expected refund amount.
  let owner_address = Address(VerificationKey(datum.owner), None)
  let paid_to_owner =
    sum_sent_to(self, owner_address, master_token_policy, master_token_name)
  expect paid_to_owner >= expected_refund_amount

  // All checks passed.
  True
}
