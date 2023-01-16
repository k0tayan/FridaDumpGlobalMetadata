console.log("Searching global-metadata.dat in memory...")
Process.enumerateRangesSync({protection: "r--", coalesce: true}).forEach(element => {
    Memory.scan(element.base, element.size, "AF 1B B1 FA", {
        onMatch(address, size){
            console.log("Metadata found at: " + address.toString())

            var found = true;
            var DefinitionsOffset = parseInt(address, 16) + 0x108;
            var DefinitionsOffset_size = Memory.readInt(ptr(DefinitionsOffset));

            var DefinitionsCount = parseInt(address, 16) + 0x10C;
            var DefinitionsCount_size = Memory.readInt(ptr(DefinitionsCount));
            while (DefinitionsCount_size < 10)
            {
                DefinitionsOffset -= 0x08;
                if (DefinitionsOffset < 0)
                {
                    found = false;
                    break;
                }
                DefinitionsOffset_size = Memory.readInt(ptr(DefinitionsOffset));

                DefinitionsCount -= 0x08;
                DefinitionsCount_size = Memory.readInt(ptr(DefinitionsCount));
            }
            if (found){
                var global_metadata_size = DefinitionsOffset_size + DefinitionsCount_size;
                console.log("Size: ", global_metadata_size);

                address.readByteArray(element.size)
                send("metadata", address.readByteArray(global_metadata_size))
            }
        }
    })
})