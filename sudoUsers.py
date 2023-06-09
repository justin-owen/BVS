import re
def list_sudo_users():
    # print("Users with Sudo permissions: ")
    with open("/etc/group") as f:
        for line in f.readlines():
            sudo = re.search("sudo",line)
            if sudo:
                sudo1 = line

    sudo_group = sudo1.split(":")
    sudo_users = sudo_group[-1]
    output = sudo_users.replace(",","\n")
    final = f"The following users have sudo permissions:\n{output}"
    print(final)
    f.close()
    append_to_file(final, "_sudoUsers")
list_sudo_users()