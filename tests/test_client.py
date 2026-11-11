
import socket
import sys

SOCKET_PATH = "./run/peercred.sock"


def run_test(name, data=None, disconnect=False,
             expected=None):

    print("\nTEST:", name)

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM
    )

    client.settimeout(8)

    try:
        client.connect(SOCKET_PATH)

        if disconnect:
            client.close()
            print("PASS: Disconnect completed")
            return True

        if data is not None:
            client.sendall(data)

        response = b""

        while b"\n" not in response:
            chunk = client.recv(256)

            if not chunk:
                break

            response += chunk

        output = response.decode(
            errors="replace"
        ).strip()

        print("Response:", output)

        if expected is not None:

            if expected in output:
                print("PASS")
                return True

            print("FAIL: Unexpected response")
            return False

        return True

    except socket.timeout:
        print("FAIL: Timeout")
        return False

    except Exception as error:
        print("FAIL:", error)
        return False

    finally:
        client.close()


print("\n====================================")
print(" PEER CREDENTIAL ACCESS GATE TESTS")
print("====================================")

results = []

results.append(run_test(
    "Valid READ request",
    b"READ|admin\n",
    expected="SUCCESS"
))

results.append(run_test(
    "Unknown operation",
    b"UNKNOWN|admin\n",
    expected="DENIED"
))

results.append(run_test(
    "Malformed request",
    b"INVALID_REQUEST\n",
    expected="ERROR"
))

results.append(run_test(
    "Empty request",
    b"\n",
    expected="ERROR"
))

results.append(run_test(
    "Incomplete request",
    b"READ|admin",
    expected="ERROR"
))

results.append(run_test(
    "Unexpected disconnect",
    disconnect=True
))

results.append(run_test(
    "Oversized request",
    b"A" * 300 + b"\n",
    expected="ERROR"
))

print("\n====================================")
print(" TEST SUMMARY")
print("====================================")

passed = sum(results)
failed = len(results) - passed

print("Total tests:", len(results))
print("Passed:", passed)
print("Failed:", failed)

if failed:
    sys.exit(1)

print("All tests passed!")
