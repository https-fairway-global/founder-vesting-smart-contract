# Aiken Linear Vesting Contract

This project implements a parameterized linear vesting contract using the [Aiken](https://aiken-lang.org/) smart contract language for the Cardano blockchain.

## Overview

This validator allows locking a specific token (identified by its PolicyId and AssetName) under a vesting schedule defined by start, cliff, and end dates. The designated beneficiary can claim vested tokens after the cliff date, according to a linear release schedule. The owner can potentially refund tokens under specific conditions (e.g., before vesting begins).

## Features

*   **Linear Vesting:** Tokens vest proportionally over time between the start and end dates.
*   **Cliff Period:** A configurable period after the start date during which no tokens can be claimed.
*   **Beneficiary Claims:** Allows the designated beneficiary to claim their vested tokens by providing the correct redeemer and signing the transaction.
*   **Owner Refunds:** (Basic implementation) Allows the contract owner to reclaim all locked tokens before the vesting start time.
*   **Parameterized:** The specific token to be vested (`PolicyId` and `AssetName`) is provided as a parameter when compiling the validator, making the script reusable for different tokens.
*   **Inline Datum:** Uses inline datums (`InlineDatum`) for storing vesting state on the UTxO.

## Project Structure

*   `aiken.toml`: Project manifest file, defines dependencies (like the Aiken standard library).
*   `validators/vesting.ak`: The core Aiken validator script implementing the vesting logic.
*   `tests/vesting_test.ak`: Unit tests for the validator logic.
*   `lib/`: (Optional) For custom Aiken library modules used by the validator or tests.
*   `build/`: Contains build artifacts generated by Aiken (ignored by git).
*   `plutus.json`: The compiled Plutus blueprint generated by `aiken build`.

## Validator Details

### Parameters

These are provided *before* compilation or applied to the blueprint using off-chain tools. They become part of the validator hash and thus the script address.

*   `master_token_policy: PolicyId` - The Policy ID of the token being vested.
*   `master_token_name: AssetName` - The Asset Name of the token being vested.

### Datum (`VestingDatum`)

This structure holds the vesting schedule and state. It must be provided as `InlineDatum` when locking funds at the script address.

```aiken
pub type VestingDatum {
  owner: VerificationKeyHash,
  beneficiary: VerificationKeyHash,
  start_time: Int, // Vesting start time (POSIX milliseconds)
  cliff_date: Int, // Cliff end time (POSIX milliseconds)
  end_date: Int, // Vesting end time (POSIX milliseconds)
  total_vesting_quantity: Int, // Total amount of the token locked
  claimed_quantity: Int, // Amount already claimed by the beneficiary
}
```

### Redeemer

This defines the actions the user intends to perform.

```aiken
pub type Redeemer {
  Claim { amount_to_claim: Int } // Beneficiary action to claim vested tokens
  Refund // Owner action to reclaim tokens (under specific conditions)
}
```

### Logic Summary

*   **`spend` Handler:** The main entry point, triggered when attempting to spend a UTxO locked at the script address.
    *   Requires the datum (`VestingDatum`) to be present (via `expect Some(datum) = datum_opt`).
    *   Dispatches to `handle_claim` or `handle_refund` based on the provided `Redeemer` (after casting it from `Data`).
*   **`handle_claim`:**
    *   Checks beneficiary signature.
    *   Checks if `current_time >= cliff_date`.
    *   Calculates total vested amount based on `current_time`.
    *   Checks if `amount_to_claim` is valid (positive and <= available vested amount).
    *   Validates that the beneficiary is paid correctly.
    *   Validates that the script UTxO is continued with the correct remaining token quantity and updated `claimed_quantity` in the datum.
*   **`handle_refund`:**
    *   Checks owner signature.
    *   Checks if `current_time < start_time`.
    *   Validates that the owner is paid the full remaining amount.
*   **Fallback `else` Handler:** Rejects any script purpose other than `spend`.

## Error Handling

The validator uses `expect` extensively to enforce conditions. If an `expect` fails, the script evaluation halts, and the transaction fails. Descriptive error messages are provided using the `@"..."` syntax to aid debugging.

## Development

### Prerequisites

*   [Aiken Installation](https://aiken-lang.org/installation-guide)

### Commands

*   **Build:** `aiken build` (Compiles the validator and outputs `plutus.json`)
*   **Check & Test:** `aiken check` (Compiles, type-checks, and runs tests defined in the `tests/` directory)

## Off-Chain Integration

To use this validator on the Cardano blockchain:

1.  **Compile & Parameterize:** Run `aiken build`. Use an off-chain tool (like Aiken's CLI, Lucid, MeshJS, PyCardano) to apply the specific `PolicyId` and `AssetName` parameters to the generated `plutus.json` blueprint. This yields the final script.
2.  **Calculate Address:** Derive the script address from the final parameterized script.
3.  **Locking Funds:** Construct a transaction that sends the `total_vesting_quantity` of the specific token (plus any necessary ADA for the UTxO) to the script address. This transaction's output must include the `VestingDatum` as `InlineDatum`.
4.  **Claiming Funds:**
    *   The beneficiary (or their agent) constructs a transaction that:
        *   Spends the UTxO locked at the script address.
        *   Provides the `Claim { amount_to_claim: ... }` redeemer.
        *   Includes the beneficiary's `VerificationKeyHash` in the `extra_signatories`.
        *   Sets the transaction `validity_range` appropriately.
        *   Pays the `amount_to_claim` to the beneficiary's address.
        *   Pays the remaining tokens back to the script address with the updated `VestingDatum` (as `InlineDatum`).
5.  **Refunding Funds:**
    *   The owner (or their agent) constructs a transaction that:
        *   Spends the UTxO locked at the script address.
        *   Provides the `Refund` redeemer.
        *   Includes the owner's `VerificationKeyHash` in the `extra_signatories`.
        *   Sets the transaction `validity_range` appropriately (must be before `start_time`).
        *   Pays the full amount back to the owner's address.

## Security Considerations

*   **Datum Validation:** Ensure off-chain code correctly constructs the initial `VestingDatum`.
*   **Parameter Application:** Securely manage the process of applying parameters to the validator blueprint.
*   **Token Identification:** The security relies on the uniqueness of the `PolicyId` and `AssetName`.
*   **Integer Overflow:** While unlikely with typical vesting quantities and durations, be mindful of potential integer overflows in calculations if dealing with extremely large numbers.
*   **Audit:** This code has not been professionally audited. Use with caution and consider a formal audit before deploying significant value. 