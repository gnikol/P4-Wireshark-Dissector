local p_multi = Proto("multi","MultiProto");

local vs_protos = {
        [2] = "mtp2",
        [3] = "mtp3",
        [4] = "alcap",
        [5] = "h248",
        [6] = "ranap",
        [7] = "rnsap",
        [8] = "nbap"
}

local f_proto = ProtoField.uint8("multi.protocol","Protocol",base.DEC,vs_protos)
local f_dir = ProtoField.uint8("multi.direction","Direction",base.DEC,{ [1] = "incoming", [0] = "outgoing"})
local f_text = ProtoField.string("multi.text","Text")

p_multi.fields = { f_proto, f_dir, f_text }

local data_dis = Dissector.get("data")

local protos = {
        [2] = Dissector.get("mtp2"),
        [3] = Dissector.get("mtp3"),
        [4] = Dissector.get("alcap"),
        [5] = Dissector.get("h248"),
        [6] = Dissector.get("ranap"),
        [7] = Dissector.get("rnsap"),
        [8] = Dissector.get("nbap"),
        [9] = Dissector.get("rrc"),
        [10] = DissectorTable.get("sctp.ppi"):get_dissector(3), -- m3ua
        [11] = DissectorTable.get("ip.proto"):get_dissector(132), -- sctp
}

function p_multi.dissector(buf,pkt,root)

        local t = root:add(p_multi,buf(0,2))
        t:add(f_proto,buf(0,1))
        t:add(f_dir,buf(1,1))

        local proto_id = buf(0,1):uint()

        local dissector = protos[proto_id]

        if dissector ~= nil then
                dissector:call(buf(2):tvb(),pkt,root)
        elseif proto_id < 2 then
                t:add(f_text,buf(2))
                -- pkt.cols.info:set(buf(2,buf:len() - 3):string())
        else
                data_dis:call(buf(2):tvb(),pkt,root)
        end

end

local wtap_encap_table = DissectorTable.get("wtap_encap")
local udp_encap_table = DissectorTable.get("udp.port")

wtap_encap_table:add(wtap.USER15,p_multi)
wtap_encap_table:add(wtap.USER12,p_multi)
udp_encap_table:add(7555,p_multi)
