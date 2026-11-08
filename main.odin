package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

// import "core:crypto/rsa"
import "./rsa"
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

    receivedRegistrationNumber : u64,
    rememberedUid : u64,
    rememberedViolation : bool,

    key_prv : rsa.Key_Private,
    key_pub : rsa.Key_Public,
}

Voter :: struct {
    person_id : u64,
    fullname : string,
    key_pub : rsa.Key_Public,
    registrationNumber : u64,
}

AnonymousVoter :: struct {
    key_pub : rsa.Key_Public,
    registrationNumber : u64,
    alreadyVoted : bool,
}

Candidate :: struct {
    id : u64,
    fullname : string,
    votes : int,
}



RegistrationBuerau :: struct {
    voters : [dynamic]Voter,
}

ElectionCommission :: struct {
    candidates : []Candidate,
    voters : [dynamic]AnonymousVoter,

    key_prv : rsa.Key_Private,
    key_pub : rsa.Key_Public,
}




Ballot :: struct {
    uid                 : u64,
    registrationNumber  : u64,
    candidate_id        : u64,
}

EncryptedBallot :: struct {
    ballot : []u8,
    signature : []u8,
}

PublicizedBallot :: struct {
    uid                 : u64,
    candidate_id        : u64,
}



main :: proc () {
    people : []Person = {
        Person{ id = 0, fullname = "Vitalya Gryb", country = .Ukraine, age = 23 },
        Person{ id = 1, fullname = "Svitlana Zhizha", country = .Ukraine, age = 27 },
        Person{ id = 2, fullname = "Zheka Zrada", country = .Ukraine, age = 19 },
        Person{ id = 3, fullname = "Grzegorz Brzeczyszczykiewicz", country = .Ukraine, age = 153 },
        Person{ id = 4, fullname = "little boy", country = .Ukraine, age = 4 },
        Person{ id = 5, fullname = "Yaroslav Aboba", country = .Ukraine, age = 34 },
        Person{ id = 6, fullname = "Vova Ugabuga", country = .Ukraine, age = 7182 },
        Person{ id = 7, fullname = "Mariya Kavun", country = .Ukraine, age = 26 },
    }



    for &p in people {
        p.key_prv, p.key_pub = rsa.keygen()
        fmt.printfln("Generated private key for %v", p.fullname)
    }
    fmt.println()




    anonymousVoters : [dynamic]AnonymousVoter

    {
        rb : RegistrationBuerau
        for i : int = 0; i < len(people); i += 1 {
            p := &people[i]


            fmt.printfln("Person %v tries to register", p.fullname)


            context.user_ptr = &p.id
            vi, vf := slice.linear_search_proc(rb.voters[:], proc (v : Voter) -> bool {
                return (v.person_id == (cast(^u64)context.user_ptr)^)
            })

            if vf {
                fmt.printfln("\tDECLINED: Person already registered")
                continue
            }



            if p.country != .Ukraine {
                fmt.printfln("\tINELIGIBLE: You have to be a citizen of Ukraine to vote")
                p.rememberedViolation = true
                continue
            }
            if p.age < 18 {
                fmt.printfln("\tINELIGIBLE: You have to be an adult to vote")
                p.rememberedViolation = true
                continue
            }

            rn := rand.uint64()

            voter := Voter{
                person_id = p.id,
                fullname = p.fullname,

                key_pub = p.key_pub,
                registrationNumber = rn,
            }
            p.receivedRegistrationNumber = rn
            append(&rb.voters, voter)
            fmt.printfln("\tVOTER REGISTERED, REGISTRATION NUMBER SENT: %v", rn)


            // violation: repeat registration
            if rand.float32() < 0.5 {
                i -= 1
            }
        }
        fmt.println()


        fmt.println("List of eligible voters")
        for v in rb.voters {
            fmt.printfln("%v", v.fullname)
        }
        fmt.println()



        for &v in rb.voters {
            av := AnonymousVoter{
                key_pub = v.key_pub,
                registrationNumber = v.registrationNumber,
                alreadyVoted = false,
            }

            append(&anonymousVoters, av)
        }
        fmt.printfln("REGISTARTION BUREAU sent anonymized voter list to ELECTION COMMISSION")
        fmt.println()
    }








    ec : ElectionCommission = {
        candidates = {
            Candidate{ 67, "Petro Poroshenko", 0 },
            Candidate{ 69, "Amogus", 0 },
        },
        voters = anonymousVoters,
    }

    ec.key_prv, ec.key_pub = rsa.keygen()
    fmt.printfln("Generated private key for ELECTION COMMISSION")
    
    EC_PUBLIC_KEY := ec.key_pub
    fmt.println()

    fmt.println("List of candidates")
    for c in ec.candidates {
        fmt.printfln("%v", c.fullname)
    }
    fmt.println()






    fmt.printfln("VOTING STARTED")
    encryptedBallots : [dynamic]EncryptedBallot
    for i : int = 0; i < len(people); i += 1 {
        p := &people[i]

        candidate := rand.choice(ec.candidates)

        ballot := Ballot{
            uid = rand.uint64(),
            registrationNumber = p.receivedRegistrationNumber,
            candidate_id = candidate.id,
        }
        if p.rememberedUid == 0 { p.rememberedUid = ballot.uid }

        eb : EncryptedBallot
        ok : bool
        eb.ballot, ok = rsa.encrypt_value(&EC_PUBLIC_KEY, ballot)
        if !ok {
            fmt.println("\tFATAL: Encryption failed")
        }
        eb.signature = rsa.sign_value(&p.key_prv, ballot)


        append(&encryptedBallots, eb)

        fmt.printfln("%v voted for %v (ID: %v)", p.fullname, candidate.fullname, ballot.uid)

        // violation: reusing ID
        if rand.float32() < 0.2 {
            append(&encryptedBallots, eb)
            fmt.printfln("\tand sent the same ballot twice")
            p.rememberedViolation = true
        } // violation: voting twice
        else if rand.float32() < 0.2 {
            i -= 1
            p.rememberedViolation = true
        }
    }
    fmt.println("VOTING ENDED")
    fmt.println()



    fmt.println("COUNTING VOTES")
    rand.shuffle(encryptedBallots[:])
    trackedIds : map[u64](struct{})
    validBallots : [dynamic]PublicizedBallot
    for eb, i in encryptedBallots {
        fmt.printfln("Processing ballot #%v", i)

        ballot, result_decrypt := rsa.decrypt_value(&ec.key_prv, eb.ballot, Ballot)
        if !result_decrypt {
            fmt.printfln("\tFATAL: failed to decrypt ballot")
            continue
        }



        fmt.printfln("\tINFO: Ballot ID: %v", ballot.uid)
        fmt.printfln("\tINFO: Registration Number: %v", ballot.registrationNumber)

        _, ok := trackedIds[ballot.uid]
        if ok {
            fmt.printfln("\tDISMISSED: Ballot with the same id received twice")
            continue
        }




        context.user_ptr = &ballot.registrationNumber
        vi, vf := slice.linear_search_proc(ec.voters[:], proc (v : AnonymousVoter) -> bool {
            return (v.registrationNumber == (cast(^u64)context.user_ptr)^)
        })

        if !vf {
            fmt.printfln("\tDISMISSED: RN %v isn't valid", ballot.registrationNumber)
            continue
        }

        if ec.voters[vi].alreadyVoted {
            fmt.printfln("\tDISMISSED: Voter with RN %v has already voted", ec.voters[vi].registrationNumber)
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








        result_verify := rsa.verify_value(&ec.voters[vi].key_pub, ballot, eb.signature)
        if !result_verify {
            fmt.printfln("\tDISMISSED: couldn't verify ballot's authenticity")
            continue
        }



        trackedIds[ballot.uid] = {}
        ec.candidates[ci].votes += 1
        ec.voters[vi].alreadyVoted = true

        // violation: dropping vote
        if rand.float32() < 0.2 {
            fmt.printfln("\tVIOLATION: Silently dropping the ballot because im evil")
        }
        else {
            append(&validBallots, PublicizedBallot{ uid = ballot.uid, candidate_id = ballot.candidate_id })
            fmt.printfln("\tACCEPTED: vote counted")
        }
    }
    fmt.println()



    fmt.printfln("ELECTION RESULTS:")
    for c in ec.candidates {
        fmt.printfln("%v:\n\t%v votes", c.fullname, c.votes)
    }

    fmt.printfln("BALLOTS:")
    for &vb in validBallots {
        context.user_ptr = &vb.candidate_id
        ci, _ := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool { return (c.id == (cast(^u64)context.user_ptr)^) })

        fmt.printfln("\tID: %v | Candidate: %v", vb.uid, ec.candidates[ci].fullname)
    }
    fmt.println()


    for &p in people {
        context.user_ptr = &p.rememberedUid
        bi, bf := slice.linear_search_proc(validBallots[:], proc (b : PublicizedBallot) -> bool { return (b.uid == (cast(^u64)context.user_ptr)^) })

        if !bf {
            fmt.printfln("%v failed to verify their vote! Remembered ID: %v", p.fullname, p.rememberedUid)
            if p.rememberedViolation {
                fmt.printfln("\t(keep in mind they violated voting process)")
            }
        }
        else {
            fmt.printfln("%v verified their vote! Remembered ID: %v", p.fullname, p.rememberedUid)
        }
    }
}
