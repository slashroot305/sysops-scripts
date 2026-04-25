import subprocess

def delete_aws_user():
    username = input("Enter the IAM username to delete: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    confirm = input(f"Are you sure you want to delete user '{username}'? Type 'yes' to confirm: ").strip().lower()

    if confirm != "yes":
        print("Deletion cancelled.")
        return

    try:
        result = subprocess.run(
            ["aws", "iam", "delete-user", "--user-name", username],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"User '{username}' deleted successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error deleting user:")
        print(e.stderr)

if __name__ == "__main__":
    delete_aws_user()