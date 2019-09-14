#![allow(unused_imports)]
#![allow(dead_code)]


use structopt::StructOpt;
use std::net::Ipv4Addr;

use pnet::packet::{ MutablePacket, Packet, PacketSize };
use pnet::packet::ipv4::{ MutableIpv4Packet, Ipv4Packet };
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{
    IcmpTypes,
    IcmpPacket,
    echo_request::MutableEchoRequestPacket,
    echo_reply::EchoReplyPacket
    };
use pnet::transport::{
    TransportProtocol::Ipv4,
    icmp_packet_iter, 
    TransportChannelType::Layer4, 
    transport_channel 
    };
use pnet::util;

static IPV4_HEADER_LEN: usize = 20;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_MAX_PAYLOAD_LEN: usize = 1472;


// type alias
type Result<T> = std::result::Result<T, Box<std::error::Error>>;

#[derive(StructOpt, Debug, Copy, Clone)]
#[structopt(name = "spring", 
    about = "Simple Ping Implementation",
    raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
struct Opt {
    /// destination IPv4 address 
    target: Ipv4Addr,

    /// number of data bytes sent
    #[structopt(short = "s", long = "size", default_value = "56")]
    pkt_size: u16,

    #[structopt(short = "c", long = "count", default_value = "4")]
    count: u8,

    /// time-to-live
    #[structopt(short = "t", long = "ttl", default_value = "54")]
    ttl: u8
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    
    let opt = Opt::from_args();
    let total_size: usize;
    if (opt.pkt_size as usize) > ICMP_MAX_PAYLOAD_LEN { 
        total_size = ICMP_MAX_PAYLOAD_LEN; 
    } else {
        total_size =  IPV4_HEADER_LEN + ICMP_HEADER_LEN + (opt.pkt_size as usize);
    }

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = transport_channel(1500, protocol).map_err(
        |e| { format!("failed to open channel: {}",e) })?;
    let mut rx = icmp_packet_iter(&mut rx);

    let mut count: u8 = 0;

    loop {
        if count > opt.count { break; }
        let ip_buf = vec![0u8; total_size];
        let icmp_buf = vec![0u8;total_size - IPV4_HEADER_LEN];
        let ip_buf = &mut *ip_buf.into_boxed_slice();
        let icmp_buf = &mut *icmp_buf.into_boxed_slice();

        let mut ip_pkt = create_ip_packet(ip_buf, opt);
        let mut icmp_pkt = create_icmp_packet(icmp_buf, opt);
        icmp_pkt.set_sequence_number(count as u16);
        ip_pkt.set_payload(icmp_pkt.packet_mut());

        count += 1;
        
        tx.send_to(ip_pkt, std::net::IpAddr::V4(opt.target))?;
        if let Ok((res, addr)) = rx.next() {
            match EchoReplyPacket::new(res.packet()) {
                Some(reply) => {
                    let seq_number = reply.get_sequence_number();
                    let len = reply.payload().len(); 
                    println!("{} bytes from {}: icmp seq={}", len, addr, seq_number);
                },
                None => {
                    println!("Malformed packet");
                    break;
                }
            }
        }
    }

   Ok(())
}

fn create_icmp_packet<'a>(
    buf: &'a mut [u8],
    opt: Opt,
    ) -> MutableEchoRequestPacket<'a> {

    let mut icmp_pkt = MutableEchoRequestPacket::new(buf).unwrap();
    let checksum = util::checksum(&icmp_pkt.packet_mut(), 2);
    icmp_pkt.set_checksum(checksum);
    icmp_pkt

}

fn create_ip_packet<'a>(buf: &'a mut [u8], opt: Opt) -> MutableIpv4Packet<'a> {
    let len = buf.len();
    let mut ip_pkt = MutableIpv4Packet::new(buf).unwrap();
    ip_pkt.set_ttl(opt.ttl);
    ip_pkt.set_header_length(IPV4_HEADER_LEN as u8);
    ip_pkt.set_total_length(len as u16);
    ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_pkt.set_destination(opt.target);
    ip_pkt
}