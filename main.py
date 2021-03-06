from equipment import Equipment
from certificate import NotValidCertificate


def main():
    # name, port = input("<name> <port>\n").split()
    # port = int(port)
    name = input("<name>\n")
    port = 8888

    equipment = Equipment(name, port)

    while True:
        try:
            print(">>")
            s = input()
            if s == "h":
                print("q => Quitter")
                print("i => Informations de l'équipement")
                print("s => Insertion en tant que server")
                print("c => Insertion en tant que client")
                print("r => Liste des équipements sur le réseau domestique")
                print("certs => Liste des certificats connus")
            elif s == "q":
                break
            elif s == "i":
                print(equipment)
            elif s == "s":
                equipment.server()
            elif s == "c":
                # server_name, server_port = input("<server_name> <server_port>\n").split()
                # server_port = int(server_port)
                server_name, server_port = "localhost", 8888
                equipment.client(server_name, server_port)
            elif s == "r":
                equipment.show_certs_couple()
            elif s == "certs":
                equipment.show_certs()
            else:
                print("Unknown command")
        except NotValidCertificate:
            print(
                "client or server fail the hand_shake because of an invalid certificate. Try again"
            )

        except KeyboardInterrupt:
            print("\nThe user interrupted the process. You can quit by pressing q")

        except Exception as e:
            # If something else happens, does not crash the programm, just resume
            print("##" * 10 + " AN ERROR OCCURED (see log below) " + "##" * 10)
            print(e)
            print("##" * 10 + " AN ERROR OCCURED (see log above) " + "##" * 10)

    print("Main loop finished")


main()
