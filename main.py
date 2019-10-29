from equipment import Equipment

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
            equipment.show_certs()
        else:
            print("Unknown command")

    except Exception as e:
        # If something happens, does not crash the programm, just resume
        print("##" * 10 + " AN ERROR OCCURED (see log below) " + "##" * 10)
        print(e)
        print("##" * 10 + " AN ERROR OCCURED (see log above) " + "##" * 10)

print("Main loop finished")
