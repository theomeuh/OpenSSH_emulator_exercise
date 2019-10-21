from equipement import Equipment

name, port = input("<name> <port>\n").split()
port = int(port)

equipment = Equipment(name, port)

while True:
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
        server_name, server_port = input("<server_name> <server_port>\n").split()
        server_port = int(server_port)
        equipment.client(server_name, server_port)
    elif s == "r":
        equipment.show_certs()
    else:
        print("Unknown command")


print("Main loop finished")
