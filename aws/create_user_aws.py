import subprocess
import argparse


def create_aws_user(username):
    try:
        result = subprocess.run(
            ["aws", "iam", "create-user", "--user-name", username],
            capture_output=True,
            text=True,
            check=True
        )
        print("User created successfully:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error creating user:")
        print(e.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create an IAM user in AWS")
    parser.add_argument("username", help="IAM username to create")
    args = parser.parse_args()
    create_aws_user(args.username)
