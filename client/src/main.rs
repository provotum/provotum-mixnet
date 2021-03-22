mod cli;
mod voting;

use async_std::task;
use clap::Clap;
use cli::cli::{Opts, SealerSubCommand, SubCommand, VASubCommand};
use voting::{
    sealer::{decrypt, keygen},
    va::{change_vote_phase, setup_question, setup_vote},
};
use voting::{va::combine_public_key_shares, va::tally_question, voter::create_votes};

fn main() {
    let opts: Opts = Opts::parse();

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match opts.subcmd {
        SubCommand::Voter(t) => {
            println!("Voter. Creating votes... {:?}", t);
            task::block_on(async {
                let result =
                    task::spawn(create_votes(t.vote, t.question, t.nr_of_votes, t.votes)).await;
                match result {
                    Ok(_) => println!("successfully created {:?} votes.", t.nr_of_votes),
                    Err(err) => println!("failed to create vote: {:?}", err),
                }
            });
        }
        SubCommand::VotingAuthority(t) => match t.subcmd {
            VASubCommand::SetupVote(t) => {
                println!("VA. Creating vote... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(setup_vote(t.vote, t.question)).await;
                    match result {
                        Ok(_) => println!("successfully created vote!"),
                        Err(err) => println!("failed to create vote: {:?}", err),
                    }
                });
            }
            VASubCommand::StoreQuestion(t) => {
                println!("VA. Store Question... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(setup_question(t.vote, t.question)).await;
                    match result {
                        Ok(_) => println!("successfully setup question!"),
                        Err(err) => println!("failed to setup question: {:?}", err),
                    }
                });
            }
            VASubCommand::SetVotePhase(t) => {
                println!("VA. Changing Vote Phase... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(change_vote_phase(t.vote, t.phase)).await;
                    match result {
                        Ok(_) => println!("successfully update vote phase!"),
                        Err(err) => println!("failed to set vote: {:?}", err),
                    }
                });
            }
            VASubCommand::CombinePublicKeyShares(t) => {
                println!("VA. Combining Public Key Shares... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(combine_public_key_shares(t.vote)).await;
                    match result {
                        Ok(_) => println!("successfully create public key!"),
                        Err(err) => println!("failed to create public key: {:?}", err),
                    }
                });
            }
            VASubCommand::TallyQuestion(t) => {
                println!("VA. Tallying Question... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(tally_question(t.vote, t.question)).await;
                    match result {
                        Ok(_) => println!("successfully tallied question!"),
                        Err(err) => println!("failed to tally question: {:?}", err),
                    }
                });
            }
        },
        SubCommand::Sealer(t) => match t.subcmd {
            SealerSubCommand::KeyGeneration(t) => {
                println!("Printing sealer - key generation... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(keygen(t.vote, t.sk, t.who)).await;
                    match result {
                        Ok(_) => println!("successfully submitted public key share!"),
                        Err(err) => println!("failed to submitted public key share: {:?}", err),
                    }
                });
            }
            SealerSubCommand::PartialDecryption(t) => {
                println!("Printing sealer - partial decryption... {:?}", t);
                task::block_on(async {
                    let result = task::spawn(decrypt(t.vote, t.question, t.sk, t.who)).await;
                    match result {
                        Ok(_) => println!("successfully submitted partial decryption!"),
                        Err(err) => println!("failed to submit partial decryption: {:?}", err),
                    }
                });
            }
        },
    }
}
