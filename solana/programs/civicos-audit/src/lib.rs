use anchor_lang::prelude::*;

declare_id!("2hnBkFjtErxbLCtTevhiW2GGTjDp1EHctshX3ebPEfRt");

const ZERO_ROOT: [u8; 32] = [0; 32];

#[program]
pub mod civicos_audit {
    use super::*;

    pub fn initialize_registry(
        ctx: Context<InitializeRegistry>,
        treasury: Pubkey,
        token_mint: Option<Pubkey>,
        token_program: Option<Pubkey>,
    ) -> Result<()> {
        require!(
            token_mint.is_some() == token_program.is_some(),
            AuditError::InvalidTokenConfig
        );

        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.treasury = treasury;
        registry.token_mint = token_mint;
        registry.token_program = token_program;
        registry.bump = ctx.bumps.registry;
        Ok(())
    }

    pub fn create_poll(
        ctx: Context<CreatePoll>,
        poll_id_hash: [u8; 32],
        poll_policy_hash: [u8; 32],
        credential_schema_hash: [u8; 32],
        opens_at: i64,
        closes_at: i64,
    ) -> Result<()> {
        require!(opens_at < closes_at, AuditError::InvalidVotingWindow);

        let poll = &mut ctx.accounts.poll;
        poll.registry = ctx.accounts.registry.key();
        poll.poll_id_hash = poll_id_hash;
        poll.creator = ctx.accounts.authority.key();
        poll.poll_policy_hash = poll_policy_hash;
        poll.credential_schema_hash = credential_schema_hash;
        poll.opens_at = opens_at;
        poll.closes_at = closes_at;
        poll.status = PollStatus::Open;
        poll.latest_nullifier_root = ZERO_ROOT;
        poll.latest_vote_commitment_root = ZERO_ROOT;
        poll.accepted_count = 0;
        poll.next_batch_index = 0;
        poll.final_result_hash = None;
        poll.bump = ctx.bumps.poll;
        Ok(())
    }

    pub fn commit_roots(
        ctx: Context<CommitRoots>,
        batch_index: u64,
        previous_nullifier_root: [u8; 32],
        nullifier_root: [u8; 32],
        previous_vote_commitment_root: [u8; 32],
        vote_commitment_root: [u8; 32],
        accepted_count_delta: u64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let poll = &mut ctx.accounts.poll;

        require!(
            poll.status == PollStatus::Open,
            AuditError::PollAlreadyFinalized
        );
        require!(now >= poll.opens_at, AuditError::PollNotOpened);
        require!(accepted_count_delta > 0, AuditError::RootBatchEmpty);
        require!(
            batch_index == poll.next_batch_index,
            AuditError::InvalidBatchIndex
        );
        require!(
            previous_nullifier_root == poll.latest_nullifier_root
                && previous_vote_commitment_root == poll.latest_vote_commitment_root,
            AuditError::InvalidRootChain
        );

        let accepted_count = poll
            .accepted_count
            .checked_add(accepted_count_delta)
            .ok_or(AuditError::AcceptedCountOverflow)?;

        poll.latest_nullifier_root = nullifier_root;
        poll.latest_vote_commitment_root = vote_commitment_root;
        poll.accepted_count = accepted_count;
        poll.next_batch_index = poll
            .next_batch_index
            .checked_add(1)
            .ok_or(AuditError::BatchIndexOverflow)?;

        let poll_root = &mut ctx.accounts.poll_root;
        poll_root.poll = poll.key();
        poll_root.batch_index = batch_index;
        poll_root.previous_nullifier_root = previous_nullifier_root;
        poll_root.nullifier_root = nullifier_root;
        poll_root.previous_vote_commitment_root = previous_vote_commitment_root;
        poll_root.vote_commitment_root = vote_commitment_root;
        poll_root.accepted_count = accepted_count;
        poll_root.submitted_by = ctx.accounts.authority.key();
        poll_root.submitted_at = now;
        poll_root.bump = ctx.bumps.poll_root;
        Ok(())
    }

    pub fn finalize_poll(
        ctx: Context<FinalizePoll>,
        final_vote_commitment_root: [u8; 32],
        final_nullifier_root: [u8; 32],
        result_hash: [u8; 32],
        tally_proof_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let poll = &mut ctx.accounts.poll;

        require!(
            poll.status == PollStatus::Open,
            AuditError::PollAlreadyFinalized
        );
        require!(now >= poll.closes_at, AuditError::PollNotClosed);
        require!(
            final_vote_commitment_root == poll.latest_vote_commitment_root
                && final_nullifier_root == poll.latest_nullifier_root,
            AuditError::InvalidFinalRoots
        );

        poll.status = PollStatus::Finalized;
        poll.final_result_hash = Some(result_hash);

        let final_result = &mut ctx.accounts.final_result;
        final_result.poll = poll.key();
        final_result.final_vote_commitment_root = final_vote_commitment_root;
        final_result.final_nullifier_root = final_nullifier_root;
        final_result.result_hash = result_hash;
        final_result.tally_proof_hash = tally_proof_hash;
        final_result.submitted_at = now;
        final_result.bump = ctx.bumps.final_result;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + PollRegistry::LEN,
        seeds = [b"registry"],
        bump
    )]
    pub registry: Account<'info, PollRegistry>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(poll_id_hash: [u8; 32])]
pub struct CreatePoll<'info> {
    #[account(
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority @ AuditError::Unauthorized
    )]
    pub registry: Account<'info, PollRegistry>,
    #[account(
        init,
        payer = authority,
        space = 8 + PollAccount::LEN,
        seeds = [b"poll", poll_id_hash.as_ref()],
        bump
    )]
    pub poll: Account<'info, PollAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_index: u64)]
pub struct CommitRoots<'info> {
    #[account(
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority @ AuditError::Unauthorized
    )]
    pub registry: Account<'info, PollRegistry>,
    #[account(
        mut,
        seeds = [b"poll", poll.poll_id_hash.as_ref()],
        bump = poll.bump,
        constraint = poll.registry == registry.key() @ AuditError::InvalidRegistry
    )]
    pub poll: Account<'info, PollAccount>,
    #[account(
        init,
        payer = authority,
        space = 8 + PollRootAccount::LEN,
        seeds = [b"poll-root", poll.key().as_ref(), &batch_index.to_le_bytes()],
        bump
    )]
    pub poll_root: Account<'info, PollRootAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizePoll<'info> {
    #[account(
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority @ AuditError::Unauthorized
    )]
    pub registry: Account<'info, PollRegistry>,
    #[account(
        mut,
        seeds = [b"poll", poll.poll_id_hash.as_ref()],
        bump = poll.bump,
        constraint = poll.registry == registry.key() @ AuditError::InvalidRegistry
    )]
    pub poll: Account<'info, PollAccount>,
    #[account(
        init,
        payer = authority,
        space = 8 + FinalResultAccount::LEN,
        seeds = [b"final-result", poll.key().as_ref()],
        bump
    )]
    pub final_result: Account<'info, FinalResultAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct PollRegistry {
    pub authority: Pubkey,
    pub treasury: Pubkey,
    pub token_mint: Option<Pubkey>,
    pub token_program: Option<Pubkey>,
    pub bump: u8,
}

impl PollRegistry {
    pub const LEN: usize = 32 + 32 + (1 + 32) + (1 + 32) + 1;
}

#[account]
pub struct PollAccount {
    pub registry: Pubkey,
    pub poll_id_hash: [u8; 32],
    pub creator: Pubkey,
    pub poll_policy_hash: [u8; 32],
    pub credential_schema_hash: [u8; 32],
    pub opens_at: i64,
    pub closes_at: i64,
    pub status: PollStatus,
    pub latest_nullifier_root: [u8; 32],
    pub latest_vote_commitment_root: [u8; 32],
    pub accepted_count: u64,
    pub next_batch_index: u64,
    pub final_result_hash: Option<[u8; 32]>,
    pub bump: u8,
}

impl PollAccount {
    pub const LEN: usize =
        32 + 32 + 32 + 32 + 32 + 8 + 8 + PollStatus::LEN + 32 + 32 + 8 + 8 + (1 + 32) + 1;
}

#[account]
pub struct PollRootAccount {
    pub poll: Pubkey,
    pub batch_index: u64,
    pub previous_nullifier_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub previous_vote_commitment_root: [u8; 32],
    pub vote_commitment_root: [u8; 32],
    pub accepted_count: u64,
    pub submitted_by: Pubkey,
    pub submitted_at: i64,
    pub bump: u8,
}

impl PollRootAccount {
    pub const LEN: usize = 32 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 1;
}

#[account]
pub struct FinalResultAccount {
    pub poll: Pubkey,
    pub final_vote_commitment_root: [u8; 32],
    pub final_nullifier_root: [u8; 32],
    pub result_hash: [u8; 32],
    pub tally_proof_hash: Option<[u8; 32]>,
    pub submitted_at: i64,
    pub bump: u8,
}

impl FinalResultAccount {
    pub const LEN: usize = 32 + 32 + 32 + 32 + (1 + 32) + 8 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum PollStatus {
    Open,
    Finalized,
}

impl PollStatus {
    pub const LEN: usize = 1;
}

#[error_code]
pub enum AuditError {
    #[msg("Only the registry authority can perform this action.")]
    Unauthorized,
    #[msg("The poll is not associated with the supplied registry.")]
    InvalidRegistry,
    #[msg("Poll opens_at must be before closes_at.")]
    InvalidVotingWindow,
    #[msg("The poll has not opened for root commits.")]
    PollNotOpened,
    #[msg("The poll has already been finalized.")]
    PollAlreadyFinalized,
    #[msg("The poll has not closed yet.")]
    PollNotClosed,
    #[msg("The submitted previous roots do not match the poll's latest roots.")]
    InvalidRootChain,
    #[msg("The submitted batch index is not the next expected batch index.")]
    InvalidBatchIndex,
    #[msg("A root batch must add at least one accepted vote.")]
    RootBatchEmpty,
    #[msg("Accepted vote count overflow.")]
    AcceptedCountOverflow,
    #[msg("Batch index overflow.")]
    BatchIndexOverflow,
    #[msg("Final roots must match the poll's latest committed roots.")]
    InvalidFinalRoots,
    #[msg("Token mint and token program must be both present or both absent.")]
    InvalidTokenConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_sizes_match_phase_5_layout() {
        assert_eq!(PollRegistry::LEN, 131);
        assert_eq!(PollAccount::LEN, 291);
        assert_eq!(PollRootAccount::LEN, 217);
        assert_eq!(FinalResultAccount::LEN, 170);
    }
}
