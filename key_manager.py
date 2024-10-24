import datetime
import pathlib

from tabulate import tabulate


def auto_revoke_stale_keys():
    key_path = pathlib.Path("keys")
    for key_type in key_path.iterdir():
        for key in key_type.iterdir():
            if (datetime.datetime.now() - datetime.datetime.fromtimestamp(key.stat().st_ctime)).days > 30:
                key.unlink()


def key_index():
    key_path = pathlib.Path("keys")
    keys = []
    for key_type in key_path.iterdir():
        keys.append([key_type.name, len(list(key_type.iterdir()))])
    print(f'\n{tabulate(keys, headers=["Key Type", "Key Count"])}')


def key_type_index():
    possible_key_types = []
    key_path = pathlib.Path("keys")
    for key_type in key_path.iterdir():
        possible_key_types.append(key_type.name)

    print("\nPossible Key Types: ")
    for n, key_type in enumerate(possible_key_types):
        print(f"{n + 1}. {key_type}")

    key_type = input("Enter Key Type: ")
    if key_type not in possible_key_types:
        print("\nInvalid Key Type")
        return

    keys = []
    key_path = pathlib.Path(f"keys/{key_type}")
    for key in key_path.iterdir():
        keys.append([key.name, key.stat().st_size, datetime.datetime.fromtimestamp(key.stat().st_ctime)])
    print(f'\n{tabulate(keys, headers=["Key", "Size (bytes)", "Created At"])}\n')

    # option to view key or revoke key
    key = input("Enter Key Name: ")
    key_path = pathlib.Path(f"keys/{key_type}/{key}")

    if not key_path.exists():
        print("\nInvalid Key\n")
        return

    while True:
        print(f"\nKey: {key}")
        print(f"1. View Key")
        print(f"2. Revoke Key")
        print(f"3. Exit")

        option = input("Enter Option: ")

        if option == "1":
            with key_path.open("rb") as f:
                print(f"\n{f.read()}")
        elif option == "2":
            key_path.unlink()
            print("\nKey Revoked")
            break
        elif option == "3":
            break
        else:
            print("\nInvalid Option")


def main():
    while True:
        print("\n1. Key Index")
        print("2. Key Type Index")
        print("3. Exit")

        option = input("Enter Option: ")

        if option == "1":
            key_index()
        elif option == "2":
            key_type_index()
        elif option == "3":
            break
        else:
            print("\nInvalid Option\n")


if __name__ == "__main__":
    main()
