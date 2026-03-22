from blp_logic import BLPSystem

def init_env():
    sys = BLPSystem()
    # Subjects
    sys.add_subject("alice", "S", "U")
    sys.add_subject("bob", "C", "C")
    sys.add_subject("eve", "U", "U")
    # Objects
    sys.add_object("pub.txt", "U")
    sys.add_object("emails.txt", "C")
    sys.add_object("username.txt", "S")
    sys.add_object("password.txt", "TS")
    return sys

def print_state(sys):
    print("\n--- Current BLP State ---")
    for name, levels in sys.subjects.items():
        print(f"[Subject] {name}: Curr={levels['curr']}, Max={levels['max']}")
    for name, lvl in sys.objects.items():
        print(f"[Object]  {name}: Lvl={lvl}")
    print("-" * 30)

def run_test(case_num):
    sys = init_env()
    print(f"\n========== CASE #{case_num} ==========")
    print("[System] Initializing Default State...")

    if case_num == 1:
        print("> Action: alice READ emails.txt...")
        sys.read("alice", "emails.txt")

    elif case_num == 2:
        print("> Action: Alice READ password.txt...")
        sys.read("alice", "password.txt")

    elif case_num == 3:
        print("> Action: Eve READ pub.txt...")
        sys.read("eve", "pub.txt")

    elif case_num == 4:
        print("> Action: Eve READ emails.txt...")
        sys.read("eve", "emails.txt")

    elif case_num == 5:
        print("> Action: Bob READ password.txt...")
        sys.read("bob", "password.txt")

    elif case_num == 6:
        print("> Action: Alice READ emails.txt...")
        sys.read("alice", "emails.txt")
        print("> Action: Alice WRITE pub.txt...")
        sys.write("alice", "pub.txt")

    elif case_num == 7:
        print("> Action: Alice READ emails.txt...")
        sys.read("alice", "emails.txt")
        print("> Action: Alice WRITE password.txt...")
        sys.write("alice", "password.txt")

    elif case_num == 8:
        print("> Action: Alice READ emails.txt...")
        sys.read("alice", "emails.txt")
        print("> Action: Alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")
        print("> Action: Alice READ username.txt...")
        sys.read("alice", "username.txt")
        print("> Action: Alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")

    elif case_num == 9:
        print("> Action: Alice READ username.txt...")
        sys.read("alice", "username.txt")
        print("> Action: Alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")
        print("> Action: Alice READ password.txt...")
        sys.read("alice", "password.txt")
        print("> Action: Alice WRITE password.txt...")
        sys.write("alice", "password.txt")

    elif case_num == 10:
        print("> Action: Alice READ pub.txt...")
        sys.read("alice", "pub.txt")
        print("> Action: Alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")
        print("> Action: Bob READ emails.txt...")
        sys.read("bob", "emails.txt")

    elif case_num == 11:
        print("> Action: Alice READ pub.txt...")
        sys.read("alice", "pub.txt")
        print("> Action: Alice WRITE username.txt...")
        sys.write("alice", "username.txt")
        print("> Action: Bob READ username.txt...")
        sys.read("bob", "username.txt")

    elif case_num == 12:
        print("> Action: Alice READ pub.txt...")
        sys.read("alice", "pub.txt")
        print("> Action: Alice WRITE password.txt...")
        sys.write("alice", "password.txt")
        print("> Action: Bob READ password.txt...")
        sys.read("bob", "password.txt")

    elif case_num == 13:
        print("> Action: Alice READ pub.txt...")
        sys.read("alice", "pub.txt")
        print("> Action: Alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")
        print("> Action: Eve READ emails.txt...")
        sys.read("eve", "emails.txt")

    elif case_num == 14:
        print("> Action: Alice READ emails.txt...")
        sys.read("alice", "emails.txt")
        print("> Action: Alice WRITE pub.txt...")
        sys.write("alice", "pub.txt")
        print("> Action: eve READ pub.txt...")
        sys.read("eve", "pub.txt")

    elif case_num == 15:
        print(sys.set_level("alice", "S"))
        print("> Action: alice READ username.txt...")
        sys.read("alice", "username.txt")

    elif case_num == 16:
        print("> Action: Alice READ emails.txt...")
        sys.read("alice", "emails.txt")
        print(sys.set_level("alice", "U"))
        print("> Action: alice WRITE pub.txt...")
        sys.write("alice", "pub.txt")
        print("> Action: eve READ pub.txt...")
        sys.read("eve", "pub.txt")

    elif case_num == 17:
        print("> Action: Alice READ username.txt...")
        sys.read("alice", "username.txt")
        print(sys.set_level("alice", "C"))
        print("> Action: alice WRITE emails.txt...")
        sys.write("alice", "emails.txt")
        print("> Action: eve READ emails.txt...")
        sys.read("eve", "emails.txt")

    elif case_num == 18:
        print("> Action: Eve READ pub.txt...")
        sys.read("eve", "pub.txt")
        print("> Action: Eve READ emails.txt...")
        sys.read("eve", "emails.txt")

    print_state(sys)

def main():
    while True:
        print("\n======================================")
        print("  Bell-LaPadula (BLP) Simulator CLI")
        print("======================================")
        print("\nOptions:")
        print("  [1-18] Run a specific test case")
        print("  [A]    Run all test cases")
        print("  [Q]    Quit")
        
        choice = input("\nEnter choice: ").upper()
        if choice == 'Q': break
        elif choice.isdigit(): 
            run_test(int(choice)) 
        elif choice == 'A':
            for i in range(1, 19): 
                run_test(i)


if __name__ == "__main__":
    main()