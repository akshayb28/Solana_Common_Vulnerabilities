# Code Quality and Security Issues in Rust Smart Contracts

## 1. Integer Overflow

Rust offers different integer types with varying ranges:

- `u8` (8 bits): 0 to 255
- `u16` (16 bits): 0 to 65535
- `u32` (32 bits): 0 to 4294967295
- `u64` (64 bits): 0 to 18446744073709551615
- `u128` (128 bits): 0 to a very large positive number

### Example

```
ub fn pretty_time(t: u64) -> String {    
let seconds = t % 60;
    let minutes = (t / 60) % 60;
    let hours = (t / (60 * 60)) % 24;
    let days = t / (60 * 60 * 24);


pub fn calculate_fee_from_amount(amount: u64, percentage: f32) -> u64 {
    if percentage <= 0.0 {
        return 0
    }
    let precision_factor: f32 = 1000000.0;
    let factor = (percentage / 100.0 * precision_factor) as u128; //largest it can get is 10^4
    (amount as u128 * factor / precision_factor as u128) as u64 // this does not fit if amount
                                                                // itself cannot fit into u64
```

### Description
Integer overflow occurs when an arithmetic operation results in a value that exceeds the maximum representable value of the chosen integer data type. It can lead to unexpected behavior in smart contracts, as the value wraps around to the minimum value instead of throwing an error.

### Remediation

Instead of using the `*` operator, use the checked_mul function to prevent overflow. Similarly, use checked_div instead of the `/` operator to prevent underflow.



## 2.Missing Account Verification

The "Missing Account Verification" issue in Rust smart contracts on the Solana blockchain typically arises when a smart contract fails to verify or check the ownership and structure of an account, potentially leading to vulnerabilities. This can occur due to various reasons, such as incorrect constructor arguments, failed contract verification, or lack of signature validation. This can lead to several problems, including Unauthorized Access, Denial-of-Service Attacks, and Loss of Funds.

### Example


```   if !acc.sender.is_signer || !acc.metadata.is_signer {
       return Err(ProgramError::MissingRequiredSignature)
   }

create.rs - Line 121:
   if a.rent.key != &sysvar::rent::id() ||
       a.token_program.key != &spl_token::id() ||
       a.associated_token_program.key != &spl_associated_token_account::id() ||
       a.system_program.key != &system_program::id()
   {
       return Err(ProgramError::InvalidAccountData)
   }
```
```create.rs - Line 85:
    if !a.sender.is_writable ||             //fee payer
        !a.sender_tokens.is_writable ||     //debtor
        !a.recipient_tokens.is_writable ||  //might be created
        !a.metadata.is_writable ||          //will be created
        !a.escrow_tokens.is_writable ||     //creditor
        !a.streamflow_treasury_tokens.is_writable || //might be created
        !a.partner_tokens.is_writable
    //might be created
    // || !a.liquidator.is_writable //creditor (tx fees)
    {
        return Err(SfError::AccountsNotWritable.into())
    }
```
### Description
Account verification is critical in Solana programs. Signed and writable accounts, as recommended, are to be verified before the business logic implementation, Also, the accounts data is verified to match the business logic requirements.



## 3.Missing Signer check
If the account provided as a signer is not included as a signer in the transaction, Solana will throw a MissingRequiredSignature error. This helps prevent the unauthorized execution of instructions.

### Example
```        let init_vesting_account = create_account(
            &payer.key,
            &vesting_account_key,
            rent.minimum_balance(state_size),
            state_size as u64,
            &program_id,
        );
```
### Description
 In the above example, An instruction should only be available to a restricted set of entities; the program should verify that the call has been signed by the appropriate entity.

### Remediation
Verify that the payer account is a signer using the is_signer() function.



## 4.Arithmetic Accuracy Deviation
Arithmetic accuracy deviations in Rust smart contracts on Solana can occur due to various factors, leading to unintended behaviour and potential security vulnerabilities. These deviations refer to situations where the outcome of mathematical operations within a smart contract differs from the expected result.

### Example
```let x = args.num_nfts_in_bucket;
  let y = args.num_nfts_in_lockers;
  let x_plus_y = (y as u64).checked_add(x as u64).unwrap();

 let numerator = args
      .locker_duration
     .checked_mul(y as u64)
      .unwrap()
      .checked_mul(100)
      .unwrap()
      .checked_mul(LAMPORTS_PER_DROPLET)
      .unwrap();

let denominator = args.max_locker_duration.checked_mul(x_plus_y).unwrap();
 let raw_interest = numerator.checked_div(denominator).unwrap();
```
### Description
 In the above example,Consider a scenario in which x = 1000, y = 1, and max_duration = t ∗ 116 sec.
• By those above conditions, a user can skip t seconds of duration for interest calculation.
• Letlocker_duration=6, andtis6sec.
• Interest=(6∗1∗100∗108)/(6∗116∗8640∗1001)=(int)0.997765=0

### Remediation
It is recommended to perform a ceiling division when calculating interest owed.



## 5.Arbitrary signed program invocation
The Arbitrary Signed Program Invocation issue in Solana refers to a vulnerability in the token instruction code that allows invoking an arbitrary program instead of the real SPL-token program. This issue can lead to security risks and potential attacks on the Solana blockchain.

In Solana, a transaction consists of one or more instructions, an array of accounts to read and write data from, and one or more signatures. Instructions are the smallest execution logic on Solana and invoke programs that make calls to the Solana runtime to update the state. Programs on Solana don't store data/state; rather, data/state is stored in accounts. When a Solana program invokes another program, the callee's program ID is supplied to the call typically through one of the following two functions: invoke or invoke_signed. The program ID is the first parameter of the instruction. In the case of the token instruction, there was a vulnerability that allowed invoking an arbitrary program, which could lead to security risks and potential attacks.

### Example
```#[program]
pub mod Issue_ASPI {
  use super::*;
  pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> ProgramResult {
   let token_program = ctx.accounts.token_program.clone();

   // Vulnerable: Allowing arbitrary program invocation
  invoke(&token_program, &ctx.accounts.token_account, &[amount.to_le_bytes().as_ref()]);
  Ok(())
 }
}
```
### Description
 In The above example, The code invokes the token_program without validating its program ID. An attacker could supply a malicious program instead, leading to unintended execution.
Exploitation:
The attacker supplies a malicious program ID as token_program.
Your program invokes the malicious program, potentially granting it unintended control over tokens or other assets.

### Remediation
 To avoid such vulnerabilities and attacks in general, it is essential to ensure that the program ID is correctly checked and validated before executing any instructions.




## 6.Solana account confusions
​​In your Solana smart contracts, remember that users can provide any type of account as input. Don't assume ownership alone guarantees the account matches your expectations. Always verify the account's data type to avoid security vulnerabilities. Solana programs often involve multiple account types for data storage. Checking account ownership isn't enough. Validate every provided account's data type against your intended use.

### Example:
```processor.rs - Line 44
        let vesting_account_key = Pubkey::create_program_address(&[&seeds], &program_id).unwrap();
        if vesting_account_key != *vesting_account.key {
            msg!("Provided vesting account is invalid");
            return Err(ProgramError::InvalidArgument);
        }
```
### Description
In the above example,The address generated using create_program_address is not guaranteed to be a valid program address off the curve. Program addresses do not lie on the ed25519 curve and, therefore, have no valid private key associated with them, and thus, generating a signature for it is impossible. There is about a 50/50 chance of this happening for a given collection of seeds and program ID.

### Remediation
To generate a valid program address using a specific seed, use find_program_address function, which iterates through multiple bump seeds until a valid combination that does not lie on the curve is found.



## 7.Error not handled
Unhandled errors in Rust Solana programs pose a significant threat to their security and functionality. These errors can lead to unexpected behavior, program crashes, and even potential financial losses. When an error occurs, the program can either handle it gracefully or leave it unhandled. Unhandled errors are those that the program doesn't explicitly handle and recover from.

### Example
```pub mod my_program {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> ProgramResult {
        // Validate inputs
        if amount == 0 {
            return Err(ProgramError::InvalidInput); // Explicit error for invalid amount
        }
        // ... (rest of the transfer logic)
        // Handle potential errors from other operations
        let transfer_result = spl_token::transfer(
            /* ... transfer parameters ... */
        );
        match transfer_result {
            Ok(()) => {
                // Transfer successful
            }
            Err(error) => {
                // Handle transfer error appropriately
                return Err(error);
            }
        }

        Ok(())
    }
```
### Description
In the Above Example, there's a potential "error not handled" issue. After calling spl_token::transfer, which presumably performs a token transfer operation, the code checks the result with a match statement. If the transfer operation fails, an error is caught, but the error is simply returned without any further handling or logging.

### Remediation
In order to mitigate the "error not handled" issue, it's recommended to include proper error handling mechanisms, such as logging the error, rolling back any state changes, or taking appropriate actions based on the specific error. Simply returning the error without any additional handling may lead to undesired behavior and make it difficult to identify and debug issues during the execution of the program.






























