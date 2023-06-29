from app import mongodb


class NetworkPacket(mongodb.Document):
    meta = {'collection': 'network_packets'} 
    
    src_ip = mongodb.StringField(required=False)
    src_port = mongodb.StringField(required=False)
    
    dst_ip = mongodb.StringField(required=False)
    dst_port = mongodb.StringField(required=False)
    protocol = mongodb.StringField(required=False)
    
    timestamp = mongodb.StringField(required=False)
    flow_duration = mongodb.StringField(required=False)
    tot_fwd_pkts = mongodb.StringField(required=False)
    tot_bwd_pkts = mongodb.StringField(required=False)
    
    totlen_fwd_pkts = mongodb.StringField(required=False)
    totlen_bwd_pkts = mongodb.StringField(required=False)
    fwd_iat_tot = mongodb.StringField(required=False)
    
    bwd_iat_tot = mongodb.StringField(required=False)
    fwd_header_len = mongodb.StringField(required=False)
    bwd_header_len = mongodb.StringField(required=False)
    fwd_pkts_s = mongodb.StringField(required=False)
    
    bwd_pkts_s = mongodb.StringField(required=False)
    flow_pkts_s = mongodb.StringField(required=False)
    flow_byts_s = mongodb.StringField(required=False)
    
    down_up_ratio = mongodb.StringField(required=False)
    init_fwd_win_byts = mongodb.StringField(required=False)
    init_bwd_win_byts = mongodb.StringField(required=False)
    
    def to_json(self):
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            
            "timestamp": self.timestamp,
            "flow_duration": self.flow_duration,
            "tot_fwd_pkts": self.tot_fwd_pkts,
            "tot_bwd_pkts": self.tot_bwd_pkts,
            
            "totlen_fwd_pkts": self.totlen_fwd_pkts,
            "totlen_bwd_pkts": self.totlen_bwd_pkts,
            "fwd_iat_tot": self.fwd_iat_tot,
            
            "bwd_iat_tot": self.bwd_iat_tot,
            "fwd_header_len": self.fwd_header_len,
            "bwd_header_len": self.bwd_header_len,
            "fwd_pkts_s": self.fwd_pkts_s,
            
            "bwd_pkts_s": self.bwd_pkts_s,
            "flow_pkts_s": self.flow_pkts_s,
            "flow_byts_s": self.flow_byts_s,
            
            "down_up_ratio": self.down_up_ratio,
            "init_fwd_win_byts": self.init_fwd_win_byts,
            "init_bwd_win_byts": self.init_bwd_win_byts
        }