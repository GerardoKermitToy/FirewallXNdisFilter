use super::Handle;
use core::slice;
use smoltcp::wire::{IpProtocol, checksum};

const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;
const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_MAX_HEADER_SIZE: usize = 60;
const IPV6_HEADER_SIZE: usize = 40;
const TCP_MIN_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const ICMP_MIN_HEADER_SIZE: u32 = 4;
const IPV4_CHECKSUM_OFFSET: u32 = 10;
const TCP_CHECKSUM_OFFSET: u32 = 16;
const UDP_CHECKSUM_OFFSET: u32 = 6;
const ICMP_CHECKSUM_OFFSET: u32 = 2;
const IPV4_FRAGMENT_MASK: u32 = 0x3fff;
const IPV6_FRAGMENT_MASK: u32 = 0xfff9;
const IPV6_EXTENSION_SIZE: usize = 8;
const MAX_IPV6_EXTENSIONS: u32 = 8;
const IPV4_OPTION_END: u8 = 0;
const IPV4_OPTION_NOP: u8 = 1;
const IPV4_OPTION_LOOSE_SOURCE_ROUTE: u8 = 131;
const IPV4_OPTION_STRICT_SOURCE_ROUTE: u8 = 137;
const IPV6_OPTION_PAD1: u8 = 0;
const IPV6_OPTION_HOME_ADDRESS: u8 = 201;
const IPV6_ROUTE_TYPE_0: u8 = 0;
const IPV6_ROUTE_TYPE_2: u8 = 2;
const IPV6_ROUTE_SEGMENT_ROUTING: u8 = 4;
const MAX_CHECKSUM_CHUNK: usize = 65534;

unsafe extern "C" {
    fn ForwardRead(nb: Handle, offset: u32, bytes: *mut u8, length: u32) -> u8;
    fn WriteForwardChecksum(nb: Handle, offset: u32, checksum: u16) -> u8;
    fn hv_wfp_sum(nb: Handle, start: u32, length: u32, field: u32, sum: *mut u64) -> u8;
    fn hv_wfp_first_nb(nbl: Handle) -> Handle;
    fn hv_wfp_next_nb(nb: Handle) -> Handle;
    fn hv_wfp_nb_length(nb: Handle) -> u32;
    fn hv_wfp_clear_checksum(nbl: Handle);
}
fn read(nb: Handle, offset: u32, bytes: &mut [u8]) -> bool {
    unsafe { ForwardRead(nb, offset, bytes.as_mut_ptr(), bytes.len() as u32) != 0 }
}
fn write(nb: Handle, offset: u32, checksum: u16) -> bool {
    unsafe { WriteForwardChecksum(nb, offset, checksum) != 0 }
}
fn u16_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}
fn finish(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn bytes_sum(bytes: &[u8], position: usize) -> u64 {
    let mut sum = 0;
    // Bound smoltcp's u32 accumulator even for a large logical offload span.
    // Even full chunks preserve the byte phase at every chunk boundary.
    for chunk in bytes.chunks(MAX_CHECKSUM_CHUNK) {
        let word = checksum::data(chunk);
        sum += u64::from(if position & 1 == 0 {
            word
        } else {
            word.swap_bytes()
        });
    }
    sum
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpChecksumSpan(bytes: *const u8, length: u32, position: u32, field: u32) -> u64 {
    if length == 0 {
        return 0;
    }
    let bytes = unsafe { slice::from_raw_parts(bytes, length as usize) };
    let position = position as usize;
    let left = (field as usize).saturating_sub(position).min(bytes.len());
    let right = (field as usize + 2)
        .saturating_sub(position)
        .min(bytes.len());
    // Exclude rather than subtract the old field: smoltcp returns folded sums.
    bytes_sum(&bytes[..left], position) + bytes_sum(&bytes[right..], position + right)
}
#[unsafe(no_mangle)]
extern "C" fn ForwardChecksum(
    nb: Handle,
    start: u32,
    length: u32,
    field: u32,
    seed: u32,
    out: *mut u16,
) -> u8 {
    let mut sum = 0;
    if unsafe { hv_wfp_sum(nb, start, length, field, &mut sum) } == 0 {
        return 0;
    }
    unsafe { out.write(finish(sum + u64::from(seed))) };
    1
}
fn packet(nb: Handle, ipv6: bool, segmented: bool, complete: &mut bool) -> bool {
    let mut ip = [0u8; IPV4_MAX_HEADER_SIZE];
    let initial = if ipv6 {
        IPV6_HEADER_SIZE
    } else {
        IPV4_MIN_HEADER_SIZE
    };
    if !read(nb, 0, &mut ip[..initial])
        || ip[0] >> 4 != if ipv6 { IPV6_VERSION } else { IPV4_VERSION }
    {
        return false;
    }
    let (total, mut transport, mut protocol, mut seed);
    if !ipv6 {
        transport = u32::from(ip[0] & 15) * 4;
        total = u16_at(&ip, 2);
        if transport < IPV4_MIN_HEADER_SIZE as u32
            || !read(
                nb,
                IPV4_MIN_HEADER_SIZE as u32,
                &mut ip[IPV4_MIN_HEADER_SIZE..transport as usize],
            )
        {
            return false;
        }
        if !segmented && (total < transport || total > unsafe { hv_wfp_nb_length(nb) }) {
            return false;
        }
        let header_sum = HvWfpChecksumSpan(ip.as_ptr(), transport, 0, IPV4_CHECKSUM_OFFSET);
        if !write(nb, IPV4_CHECKSUM_OFFSET, finish(header_sum)) {
            return false;
        }
        if segmented || u16_at(&ip, 6) & IPV4_FRAGMENT_MASK != 0 {
            *complete = false;
            return true;
        }
        protocol = IpProtocol::from(ip[9]);
        seed = u32::from(checksum::data(&ip[12..20]));
        let mut option = IPV4_MIN_HEADER_SIZE;
        while option < transport as usize {
            let kind = ip[option];
            if kind == IPV4_OPTION_END {
                break;
            }
            if kind == IPV4_OPTION_NOP {
                option += 1;
                continue;
            }
            if transport as usize - option < 2 {
                return false;
            }
            let length = usize::from(ip[option + 1]);
            if length < 2 || length > transport as usize - option {
                return false;
            }
            if kind == IPV4_OPTION_LOOSE_SOURCE_ROUTE || kind == IPV4_OPTION_STRICT_SOURCE_ROUTE {
                if length < 7 || (length - 3) % 4 != 0 || ip[option + 2] < 4 {
                    return false;
                }
                if usize::from(ip[option + 2]) <= length {
                    seed = u32::from(checksum::data(&ip[12..16]))
                        + u32::from(checksum::data(&ip[option + length - 4..option + length]));
                }
            }
            option += length;
        }
    } else {
        if segmented {
            *complete = false;
            return true;
        }
        total = IPV6_HEADER_SIZE as u32 + u16_at(&ip, 4);
        if total > unsafe { hv_wfp_nb_length(nb) } {
            return false;
        }
        transport = IPV6_HEADER_SIZE as u32;
        protocol = IpProtocol::from(ip[6]);
        let mut addresses = [0u8; 32];
        addresses.copy_from_slice(&ip[8..40]);
        let mut steps = 0;
        while matches!(
            protocol,
            IpProtocol::HopByHop
                | IpProtocol::Ipv6Route
                | IpProtocol::Ipv6Opts
                | IpProtocol::Ipv6Frag
                | IpProtocol::IpSecAh
        ) {
            let mut extension = [0u8; IPV6_EXTENSION_SIZE];
            steps += 1;
            if steps > MAX_IPV6_EXTENSIONS
                || total - transport < IPV6_EXTENSION_SIZE as u32
                || !read(nb, transport, &mut extension)
            {
                return false;
            }
            let length = match protocol {
                IpProtocol::Ipv6Frag => IPV6_EXTENSION_SIZE as u32,
                IpProtocol::IpSecAh => (u32::from(extension[1]) + 2) * 4,
                _ => (u32::from(extension[1]) + 1) * 8,
            };
            if length > total - transport {
                return false;
            }
            if protocol == IpProtocol::Ipv6Frag && u16_at(&extension, 2) & IPV6_FRAGMENT_MASK != 0 {
                *complete = false;
                return true;
            }
            if protocol == IpProtocol::Ipv6Route && extension[3] != 0 {
                let destination = if (extension[2] == IPV6_ROUTE_TYPE_0
                    && length >= 24
                    && (length - 8) % 16 == 0
                    && u32::from(extension[3]) <= (length - 8) / 16)
                    || (extension[2] == IPV6_ROUTE_TYPE_2 && length == 24 && extension[3] == 1)
                {
                    transport + length - 16
                } else if extension[2] == IPV6_ROUTE_SEGMENT_ROUTING
                    && length >= 8 + (u32::from(extension[4]) + 1) * 16
                    && u32::from(extension[3]) <= u32::from(extension[4]) + 1
                {
                    transport + 8
                } else {
                    return false;
                };
                if !read(nb, destination, &mut addresses[16..]) {
                    return false;
                }
            }
            if protocol == IpProtocol::Ipv6Opts {
                let mut option = 2;
                while option < length {
                    let mut item = [0u8; 2];
                    if !read(nb, transport + option, &mut item[..1]) {
                        return false;
                    }
                    if item[0] == IPV6_OPTION_PAD1 {
                        option += 1;
                        continue;
                    }
                    if length - option < 2
                        || !read(nb, transport + option, &mut item)
                        || u32::from(item[1]) > length - option - 2
                    {
                        return false;
                    }
                    if item[0] == IPV6_OPTION_HOME_ADDRESS
                        && (item[1] != 16
                            || !read(nb, transport + option + 2, &mut addresses[..16]))
                    {
                        return false;
                    }
                    option += 2 + u32::from(item[1]);
                }
            }
            protocol = IpProtocol::from(extension[0]);
            transport += length;
        }
        seed = u32::from(checksum::data(&addresses));
    }
    let mut length = total - transport;
    let field;
    let mut header = [0u8; TCP_MIN_HEADER_SIZE];
    match protocol {
        IpProtocol::Tcp => {
            if length < TCP_MIN_HEADER_SIZE as u32 || !read(nb, transport, &mut header) {
                return false;
            }
            let size = u32::from(header[12] >> 4) * 4;
            if size < TCP_MIN_HEADER_SIZE as u32 || size > length {
                return false;
            }
            field = TCP_CHECKSUM_OFFSET;
        }
        IpProtocol::Udp => {
            if length < UDP_HEADER_SIZE as u32
                || !read(nb, transport, &mut header[..UDP_HEADER_SIZE])
            {
                return false;
            }
            let udp = u16_at(&header, 4);
            if udp < UDP_HEADER_SIZE as u32 || udp > length {
                return false;
            }
            length = udp;
            field = UDP_CHECKSUM_OFFSET;
        }
        value
            if value
                == if ipv6 {
                    IpProtocol::Icmpv6
                } else {
                    IpProtocol::Icmp
                } =>
        {
            if length < ICMP_MIN_HEADER_SIZE {
                return false;
            }
            field = ICMP_CHECKSUM_OFFSET;
        }
        _ => return true,
    }
    if protocol == IpProtocol::Icmp {
        seed = 0;
    } else {
        seed += u32::from(u8::from(protocol)) + (length >> 16) + (length & 0xffff);
    }
    let mut checksum = 0;
    if ForwardChecksum(nb, transport, length, field, seed, &mut checksum) == 0 {
        return false;
    }
    if protocol == IpProtocol::Udp && checksum == 0 {
        checksum = 0xffff;
    }
    write(nb, transport + field, checksum)
}
pub(super) fn restore_nbl(nbl: Handle, ipv6: bool, segmented: bool) -> bool {
    let mut nb = unsafe { hv_wfp_first_nb(nbl) };
    if nb.is_null() {
        return false;
    }
    let mut complete = true;
    while !nb.is_null() {
        if !packet(nb, ipv6, segmented, &mut complete) {
            return false;
        }
        nb = unsafe { hv_wfp_next_nb(nb) };
    }
    if complete {
        unsafe { hv_wfp_clear_checksum(nbl) };
    }
    true
}
#[unsafe(no_mangle)]
extern "C" fn RestoreForwardChecksums(nbl: Handle, ipv6: u8, segmented: u8) -> u8 {
    u8::from(!nbl.is_null() && restore_nbl(nbl, ipv6 != 0, segmented != 0))
}
