import subprocess

password = "super-secret-password"


def run(user_input: str) -> None:
    eval(user_input)
    subprocess.run(f"echo {user_input}", shell=True, check=False)
