use aiken/crypto.{VerificationKeyHash}
use aiken/interval
use aiken/option.{Some}
// Import types and validator

use aiken/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
  placeholder as tx_placeholder,
}
use cardano/address.{Address, ScriptCredential, VerificationKey}
// Need Address constructors
use cardano/assets.{Value, add, from_lovelace, quantity_of}
// tests/vesting_test.ak
use fairway/vesting/validators/vesting.{Claim, Refund, VestingDatum, vesting}

// Need asset functions

// --- Helper Functions for Test Data ---

fn mock_owner_hash() -> VerificationKeyHash {
  #"00000000000000000000000000000000000000000000000000000001"
}

fn mock_beneficiary_hash() -> VerificationKeyHash {
  #"00000000000000000000000000000000000000000000000000000002"
}

fn mock_policy_id() -> ByteArray {
  #"11111111111111111111111111111111111111111111111111111111"
}

fn mock_asset_name() -> ByteArray {
  #"56657374696e67546f6b656e"
  // "VestingToken" hex encoded
}

fn mock_output_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

fn mock_script_hash() -> ByteArray {
  #"11111111111111111111111111111111111111111111111111111111"
}

fn mock_script_address() -> Address {
  Address(ScriptCredential(mock_script_hash()), None)
}

// --- Transaction Builder Helpers ---

fn set_validity_range(tx: Transaction, start: Int) -> Transaction {
  Transaction { ..tx, validity_range: interval.after(start) }
}

fn add_signatory(tx: Transaction, key_hash: VerificationKeyHash) -> Transaction {
  Transaction { ..tx, extra_signatories: [key_hash, ..tx.extra_signatories] }
}

// Helper to create an Input
fn create_input(
  ref: OutputReference,
  address: Address,
  value: Value,
  datum: Datum,
) -> Input {
  Input {
    output_reference: ref,
    output: Output { address, value, datum, reference_script: None },
  }
}

// Helper to add an Input to a Transaction
fn add_input(tx: Transaction, input: Input) -> Transaction {
  Transaction { ..tx, inputs: [input, ..tx.inputs] }
}

// Helper to add an Output to a Transaction
fn add_output(
  tx: Transaction,
  address: Address,
  value: Value,
  datum: Datum,
) -> Transaction {
  Transaction {
    ..tx,
    outputs: [
      Output { address, value, datum, reference_script: None },
      ..tx.outputs
    ],
  }
}

// --- Tests ---

// Test successful claim after cliff
test handle_claim_success_after_cliff() {
  let start = 1000
  let cliff = 2000
  let end = 3000
  let current_time = 2500
  // After cliff, before end
  let total_qty = 1000
  let initial_lovelace = 2_000_000
  // Ada locked with the token
  let claimed_qty = 0
  let amount_to_claim = 500

  // Should be vested: 750 available
  let owner = mock_owner_hash()
  let beneficiary = mock_beneficiary_hash()
  let policy = mock_policy_id()
  let asset = mock_asset_name()
  let own_ref = mock_output_ref(0)
  // UTxO being spent
  let script_address = mock_script_address()
  let beneficiary_address = Address(VerificationKey(beneficiary), None)

  let input_datum =
    VestingDatum {
      owner,
      beneficiary,
      start_time: start,
      cliff_date: cliff,
      end_date: end,
      total_vesting_quantity: total_qty,
      claimed_quantity: claimed_qty,
    }

  let input_value =
    from_lovelace(initial_lovelace) |> add(policy, asset, total_qty)

  // Input being spent by the script
  let script_input =
    create_input(own_ref, script_address, input_value, InlineDatum(input_datum))

  // Output paying the beneficiary
  let beneficiary_payment =
    from_lovelace(1_000_000) |> add(policy, asset, amount_to_claim)

  // Updated datum for the continuing output
  let output_datum =
    VestingDatum {
      owner: input_datum.owner,
      beneficiary: input_datum.beneficiary,
      start_time: input_datum.start_time,
      cliff_date: input_datum.cliff_date,
      end_date: input_datum.end_date,
      total_vesting_quantity: input_datum.total_vesting_quantity,
      claimed_quantity: claimed_qty + amount_to_claim,
    }

  // Remaining value for the continuing output
  let remaining_value =
    from_lovelace(initial_lovelace)
      |> add(policy, asset, total_qty - amount_to_claim)

  // Construct the transaction
  let tx =
    tx_placeholder
      |> set_validity_range(start: current_time)
      |> add_signatory(beneficiary)
      |> add_input(script_input)
      |> add_output(beneficiary_address, beneficiary_payment, NoDatum)
      |> add_output(script_address, remaining_value, InlineDatum(output_datum))

  // Call the validator handler directly
  // Parameters are passed first when calling the handler directly
  vesting(policy, asset).spend(
    Some(input_datum),
    Claim { amount_to_claim },
    own_ref,
    tx,
  )
}

// Test claim failure before cliff
test handle_claim_fail_before_cliff() {
  let start = 1000
  let cliff = 2000
  let current_time = 1500
  // Before cliff
  let policy = mock_policy_id()
  let asset = mock_asset_name()
  let own_ref = mock_output_ref(0)
  let beneficiary = mock_beneficiary_hash()

  let input_datum =
    VestingDatum {
      owner: mock_owner_hash(),
      beneficiary,
      start_time: start,
      cliff_date: cliff,
      end_date: 3000,
      total_vesting_quantity: 1000,
      claimed_quantity: 0,
    }

  // Only need validity range and signature for this test
  let tx =
    tx_placeholder
      |> set_validity_range(start: current_time)
      |> add_signatory(beneficiary)

  // Expect the call to fail (return False)
  !vesting(policy, asset).spend(
    Some(input_datum),
    Claim { amount_to_claim: 100 },
    // Amount doesn't matter, time check fails
    own_ref,
    tx,
  )
}
// TODO: Add helpers for adding inputs/outputs if needed 
