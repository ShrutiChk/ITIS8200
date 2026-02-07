import os
import json
import hashlib

hash_file_json = 'hash_table.json'

def hash_file(file_path, algorithm = 'sha256'):

    #print(f"Hashing file: {file_path}")

    # taking the hash function
    hash_func = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)

    hash_value = hash_func.hexdigest()
    #print(f"Hash ({algorithm}): {hash_value}")

    return hash_value


def traverse_directory(directory):
    hash_files_list = {}
    #print(f"Traversing directory: {directory}")

    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            #print(f"Found file: {file_path}")
            hash_value = hash_file(file_path)
            hash_files_list[file_path] = hash_value

    return hash_files_list


def generate_hash_table():
    print("Generating a new hash table")

    directory = input("Enter a directory path to where the files are that need to be hashed are: ")
    print(f"Directory: {directory}")

    if not os.path.isdir(directory):
        print("The provided path is not a valid directory.")
        return
    
    hash_files = traverse_directory(directory)

    # printing hash table 
    print("Hash table generated:")
    for file_path, hash_value in hash_files.items():
        print(f"File: {file_path}, Hash: {hash_value}")

    # storing the json table 
    with open(hash_file_json, 'w') as json_file:
        json.dump(hash_files, json_file)
    print(f"Hash table saved to {hash_file_json}")


def verify_hashes():
    print("Verifying hashes")

    directory_file_path_list = []
    missing_files = []
    renamed_files = False

    with open(hash_file_json, 'r') as json_file:
        hash_files = json.load(json_file)

    updated_hash_files = hash_files.copy()
    first_filepath = list(hash_files.keys())[0]
    target_directory = os.path.dirname(first_filepath)
    #print(f"Target directory for verification: {target_directory}")

    for root, dirs, files in os.walk(target_directory):
        for filename in files:
            directory_file_path = os.path.join(root, filename)
            directory_file_path_list.append(directory_file_path)

    for file_path, original_hash in hash_files.items():

        # missing file
        if file_path not in directory_file_path_list:
            missing_files.append(file_path)
            continue
        
        # verify hash
        current_hash = hash_file(file_path)
        if current_hash != original_hash:
            print(f"Hash is invalid for {os.path.basename(file_path)}")
        else:
            print(f"Hash is valid for {os.path.basename(file_path)}.")

    # newly created file
    for file_path in directory_file_path_list:
        if file_path not in hash_files:
            current_hash = hash_file(file_path)

            # find rename
            for missing_path in missing_files:
                if current_hash == hash_files[missing_path]:
                    old_file_name = os.path.basename(missing_path)
                    new_file_name = os.path.basename(file_path)
                    print(f" File name change detected, File {old_file_name} is renamed to the file {new_file_name}.")
                    #updating hash table
                    if missing_path in updated_hash_files:
                        del updated_hash_files[missing_path]
                    updated_hash_files[file_path] = current_hash
                    renamed_files = True
                    missing_files.remove(missing_path)
                    break
            # find newly created file
            if current_hash not in hash_files.values():
                print(f"File {os.path.basename(file_path)} is newly created")
            continue
    # deleted files
    for missing_path in missing_files:
        print(f"File {os.path.basename(missing_path)} is deleted")

    # updating hash table
    if renamed_files:
        print("Updating hash table json with changes")
        with open(hash_file_json, 'w') as json_file:
            json.dump(updated_hash_files, json_file)
        print("Hash table updated successfully.")


def main():

    # take user input
    print("Select your desired action:")
    print("1. Generate a New Hash Table")
    print("2. Verify Hashes")

    user_input = input("Enter 1 or 2: ")

    if user_input == "1":
        generate_hash_table()
    elif user_input == "2":
        verify_hashes()
    else:
        print("Invalid input. Please enter 1 or 2.")

if __name__ == "__main__":
    main()