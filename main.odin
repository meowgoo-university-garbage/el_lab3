package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "core:crypto/rsa"
import "core:crypto/hash"

Country :: enum {
    Ukraine,
    Russia,
    Poland,
}

Person :: struct {
    id : u64,
    fullname : string,
    country : Country,
    age : int,

    key_prv : rsa.Private_Key,
    key_pub : rsa.Public_Key,
}

Voter :: struct {
    id : u64,
    fullname : string,
    key_pub : rsa.Public_Key,
    alreadyVoted : bool,
}

Candidate :: struct {
    id : u64,
    fullname : string,
    votes : int,
}

ElectionCommission :: struct {
    candidates : []Candidate,

    key_prv : rsa.Private_Key,
    key_pub : rsa.Public_Key,
}

Ballot :: struct {
    voter_id     : u64,
    candidate_id : u64,
}

EncryptedBallot :: struct {
    ballot : []u8,
    signature : []u8,
}

main :: proc () {
    voter_v0 := Person{ id = 0, fullname = "Vitalya Gryb", country = .Ukraine, age = 23 }
    voter_v1 := Person{ id = 1, fullname = "Svitlana Zhizha", country = .Ukraine, age = 23 }
    voter_f0 := Person{ id = 2, fullname = "Zheka Zrada", country = .Russia, age = 23 }

    people : []^Person = {
        &voter_v0,
        &voter_v1,
        &voter_f0,
    }



    for p in people {
        result := rsa.private_key_generate(&p.key_prv)
        if result {
            fmt.printfln("Generated private key for %v", p.fullname)
        }
        else {
            fmt.printfln("Failed to generate private key for %v", p.fullname)
            continue
        }

        rsa.public_key_set_priv(&p.key_pub, &p.key_prv)
    }
    fmt.println()



    fmt.println("Forming a list of eligible voters")
    voters : [dynamic]Voter
    for &p in people {
        fmt.printfln("Examining %v", p.fullname)

        if p.country != .Ukraine {
            fmt.printfln("\tINELIGIBLE: You have to be a citizen of Ukraine to vote")
            continue
        }
        if p.age < 18 {
            fmt.printfln("\tINELIGIBLE: You have to be an adult to vote")
            continue
        }

        fmt.printfln("\tVOTER REGISTERED")
        append(&voters, Voter{ p.id, p.fullname, p.key_pub, false })
    }
    fmt.println()

    fmt.println("List of eligible voters")
    for v in voters {
        fmt.printfln("%v", v.fullname)
    }
    fmt.println()



    ec : ElectionCommission = {
        candidates = {
            Candidate{ 67, "Petro Poroshenko", 0 },
            Candidate{ 69, "Amogus", 0 },
        }
    }

    if rsa.private_key_generate(&ec.key_prv) {
        fmt.printfln("Generated private key for ELECTION COMMISSION")
    }
    else {
        fmt.printfln("Failed to generate private key for ELECTION COMMISSION")
    }
    
    rsa.public_key_set_priv(&ec.key_pub, &ec.key_prv)
    EC_PUBLIC_KEY := ec.key_pub
    fmt.println()



    fmt.println("List of candidates")
    for c in ec.candidates {
        fmt.printfln("%v", c.fullname)
    }
    fmt.println()



    fmt.printfln("VOTING STARTED")
    encryptedBallots : [dynamic]EncryptedBallot
    for &p in people {
        ballot := Ballot{
            voter_id = p.id,
            candidate_id = rand.choice(ec.candidates).id,
        }

        if rand.float32() < 0.1 {
            ballot.voter_id = rand.choice(voters[:]).id
        }

        if rand.float32() < 0.1 {
            ballot.candidate_id = cast(u64)rand.int63()
        }

        fmt.printf("%v", p.fullname)
        if ballot.voter_id != p.id {
            context.user_ptr = &ballot.voter_id
            vi, _ := slice.linear_search_proc(voters[:], proc (v : Voter) -> bool {
                return (v.id == (cast(^u64)context.user_ptr)^)
            })

            fmt.printf(" impersonates %v and", voters[vi].fullname)
        }

        context.user_ptr = &ballot.candidate_id
        ci, cf := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool {
            return (c.id == (cast(^u64)context.user_ptr)^)
        })

        if cf {
            fmt.printfln(" votes for %v", ec.candidates[ci].fullname)
        }
        else {
            fmt.printfln(" votes for an invalid candidate with id %v", ballot.candidate_id)
        }



        eb : EncryptedBallot = {
            ballot    = make([]u8, rsa.public_key_size(&EC_PUBLIC_KEY)),
            signature = make([]u8, rsa.public_key_size(&EC_PUBLIC_KEY)),
        }
        result_encrypt := rsa.encrypt_oaep(
            &EC_PUBLIC_KEY,
            .SHA512,
            slice.bytes_from_ptr(&ballot, size_of(Ballot)),
            eb.ballot)
        if !result_encrypt {
            fmt.printfln("FAILED TO ENCRYPT BALLOT")
        }

        result_sign := rsa.sign_pkcs1(
            &p.key_prv,
            .SHA512,
            slice.bytes_from_ptr(&ballot, size_of(Ballot)),
            eb.signature)
        if !result_sign {
            fmt.printfln("FAILED TO SIGN BALLOT")
        }

        append(&encryptedBallots, eb)

        if rand.float32() < 0.1 {
            append(&encryptedBallots, eb)
        }
    }
    fmt.println("VOTING ENDED")
    fmt.println()



    fmt.println("COUNTING VOTES")
    rand.shuffle(encryptedBallots[:])
    for eb, i in encryptedBallots {
        fmt.printfln("Processing ballot #%v", i)

        ballot : Ballot

        _, result_decrypt := rsa.decrypt_oaep(
            &ec.key_prv,
            .SHA512,
            eb.ballot,
            slice.bytes_from_ptr(&ballot, size_of(Ballot)))
        if !result_decrypt {
            fmt.printfln("\tFATAL: failed to decrypt ballot")
            continue
        }

        // fmt.printfln("Ballot: %v", ballot)

        context.user_ptr = &ballot.voter_id
        pi, _ := slice.linear_search_proc(people, proc (p : ^Person) -> bool {
            return (p.id == (cast(^u64)context.user_ptr)^)
        })

        fmt.printfln("\tINFO: Ballot sender: %v", people[pi].fullname)

        context.user_ptr = &ballot.voter_id
        vi, vf := slice.linear_search_proc(voters[:], proc (v : Voter) -> bool {
            return (v.id == (cast(^u64)context.user_ptr)^)
        })

        if !vf {
            fmt.printfln("\tDISMISSED: %v is not eligible for voting", people[pi].fullname)
            continue
        }

        if voters[vi].alreadyVoted {
            fmt.printfln("\tDISMISSED: %v has already voted", people[pi].fullname)
            continue
        }

        context.user_ptr = &ballot.candidate_id
        ci, cf := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool {
            return (c.id == (cast(^u64)context.user_ptr)^)
        })

        if !cf {
            fmt.printfln("\tDISMISSED: candidate with id %v doesn't exist", ballot.candidate_id)
            continue
        }

        fmt.printfln("\tINFO: Chosen candidate: %v", ec.candidates[ci].fullname)




        result_verify := rsa.verify_pkcs1(
            &voters[vi].key_pub,
            .SHA512,
            slice.bytes_from_ptr(&ballot, size_of(Ballot)),
            eb.signature)

        if !result_verify {
            fmt.printfln("\tDISMISSED: couldn't verify ballot's authenticity")
            continue
        }



        ec.candidates[ci].votes += 1
        voters[vi].alreadyVoted = true
        fmt.printfln("\tACCEPTED: vote counted")
    }
    fmt.println()



    fmt.printfln("ELECTION RESULTS:")
    for c in ec.candidates {
        fmt.printfln("%v:\n\t%v votes", c.fullname, c.votes)
    }
}
