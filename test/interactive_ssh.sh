#! /usr/bin/expect

set timeout 5

# Start the SSH process
spawn ssh -o NoHostAuthenticationForLocalhost=yes -p 2222 localhost whoami

# Pass the correct prompts
expect "Password:" {
    send "foo\r"

    expect "Token:" {
        send "bar\r"
    }
}

# Wait for the command to finish
wait
