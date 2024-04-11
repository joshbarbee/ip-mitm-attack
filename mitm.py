import socket

def get_network_adapter():
    adapters = socket.if_nameindex()

    print("Select the network adapter to use (by name or number)")

    adapters_map = {}

    for adapter_number, adapter_name in adapters:
        print(f"{adapter_number}: {adapter_name}")
        adapters_map[adapter_number] = adapter_name

    while True:
        selected_adapter = input("> ")

        if len(selected_adapter) == 0:
            continue

        if len(selected_adapter) < 2 and selected_adapter[0].isnumeric():
            # assume length less than 2 is int
            try:
                selected_adapter_num = int(selected_adapter)
                return adapters_map[selected_adapter_num]
            except:
                print("Unable to determine selected adapter as integer. Try full name")
                continue

        for v in adapters_map.values():
            if v == selected_adapter:
                return v
            
        print("Unable to determine adapter. Try again")
        
print(get_network_adapter())