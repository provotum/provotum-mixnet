use clap::Clap;

/// The Provotum CLI to impersonate voters, the voting-authority and sealers
#[derive(Clap, Debug)]
#[clap(
    name = "provotum-cli",
    version = "1.0",
    author = "Moritz Eck <moritz.eck@gmail.com>"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Clap, Debug)]
pub enum SubCommand {
    #[clap(name = "voter")]
    Voter(Voter),
    #[clap(name = "va")]
    VotingAuthority(VotingAuthority),
    #[clap(name = "sealer")]
    Sealer(Sealer),
}

/// A subcommand for controlling the Voter
#[derive(Clap, Debug)]
pub struct Voter {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The id of the question
    #[clap(short, long)]
    pub question: String,
    /// The number of votes to create
    #[clap(long)]
    pub nr_of_votes: usize,
    /// The set of allowed votes
    #[clap(long)]
    pub votes: Vec<u32>,
}

/// A subcommand for controlling the Voting Authority
#[derive(Clap, Debug)]
pub struct VotingAuthority {
    /// The voting authority subcommands
    #[clap(subcommand)]
    pub subcmd: VASubCommand,
}

#[derive(Clap, Debug)]
pub enum VASubCommand {
    #[clap(name = "setup")]
    SetupVote(SetupVote),
    #[clap(name = "store_question")]
    StoreQuestion(StoreQuestion),
    #[clap(name = "set_phase")]
    SetVotePhase(SetVotePhase),
    #[clap(name = "combine_pk_shares")]
    CombinePublicKeyShares(CombinePublicKeyShares),
    #[clap(name = "tally_question")]
    TallyQuestion(TallyQuestion),
    #[clap(name = "result")]
    GetResult(GetResult),
}

/// A subcommand for setting up the vote
#[derive(Clap, Debug)]
pub struct SetupVote {
    /// The name of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The question to store
    #[clap(short, long)]
    pub question: String,
}

/// A subcommand for setting up vote questions
#[derive(Clap, Debug)]
pub struct StoreQuestion {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The question to store
    #[clap(short, long)]
    pub question: String,
}

/// A subcommand for changing the vote phase
#[derive(Clap, Debug)]
pub struct SetVotePhase {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The vote phase
    #[clap(short, long, possible_values = &["KeyGeneration", "Voting", "Tallying"])]
    pub phase: String,
}

/// A subcommand to combine the public key shares
#[derive(Clap, Debug)]
pub struct CombinePublicKeyShares {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
}

/// A subcommand to combine the decrypted shares for a question
#[derive(Clap, Debug)]
pub struct TallyQuestion {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The id of the question
    #[clap(short, long)]
    pub question: String,
}

/// A subcommand to fetch result for a question
#[derive(Clap, Debug)]
pub struct GetResult {
    /// The id of the question
    #[clap(short, long)]
    pub question: String,
}

/// A subcommand for controlling the Sealer
#[derive(Clap, Debug)]
pub struct Sealer {
    /// The sealer subcommands
    #[clap(subcommand)]
    pub subcmd: SealerSubCommand,
}

#[derive(Clap, Debug)]
pub enum SealerSubCommand {
    #[clap(name = "keygen")]
    KeyGeneration(KeyGeneration),
    #[clap(name = "decrypt")]
    PartialDecryption(PartialDecryption),
}

/// A subcommand for controlling the key generation
#[derive(Clap, Debug)]
pub struct KeyGeneration {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The private key as string
    #[clap(short, long)]
    pub sk: String,
    /// The name of the sealer to use
    #[clap(short, long, required = true, possible_values = &["bob", "charlie"])]
    pub who: String,
}

/// A subcommand for controlling the partial decryption
#[derive(Clap, Debug)]
pub struct PartialDecryption {
    /// The id of the vote
    #[clap(short, long)]
    pub vote: String,
    /// The id of the question
    #[clap(short, long)]
    pub question: String,
    /// The private key as string
    #[clap(short, long)]
    pub sk: String,
    /// The name of the sealer to use
    #[clap(short, long, required = true, possible_values = &["bob", "charlie"])]
    pub who: String,
}
