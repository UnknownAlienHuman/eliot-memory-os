//! Fail-closed Windows TCP listener ownership observation.
//!
//! `GetExtendedTcpTable` is isolated here so provider-neutral callers never
//! parse shell output or infer ownership from endpoint liveness. Only the
//! exact IPv4/IPv6 loopback socket requested by the caller is admitted.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Hard upper bound for one IP Helper listener table allocation.
const MAX_TCP_TABLE_BYTES: usize = 1024 * 1024;

#[cfg(windows)]
struct OwnerTable {
    words: Vec<usize>,
    byte_len: usize,
}

/// Exact OS observation for one loopback TCP listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpListenerOwnerObservation {
    endpoint: SocketAddr,
    process_id: u32,
}

impl TcpListenerOwnerObservation {
    /// Returns the exact loopback endpoint used for the owner query.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns the unique owning process identifier reported by Windows.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }
}

/// Failure to prove a unique owner for one exact loopback listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpListenerOwnerError {
    /// The requested endpoint was not exact IPv4/IPv6 localhost with a port.
    InvalidEndpoint,
    /// No exact listener row existed.
    Missing,
    /// More than one exact listener row existed, even when PIDs were equal.
    Ambiguous,
    /// Windows denied the ownership observation.
    AccessDenied,
    /// The table size changed between the sizing and retrieval calls.
    SizeRace,
    /// The required allocation exceeded the explicit bound.
    BufferLimitExceeded,
    /// The returned table length, row count, port, or PID was malformed.
    MalformedTable,
    /// The API or address family is unsupported.
    UnsupportedPlatform,
    /// Another Win32 status prevented a trustworthy classification.
    Windows { code: u32 },
}

impl fmt::Display for TcpListenerOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => {
                formatter.write_str("TCP owner endpoint is not exact loopback")
            }
            Self::Missing => formatter.write_str("exact TCP listener owner is missing"),
            Self::Ambiguous => formatter.write_str("exact TCP listener owner is ambiguous"),
            Self::AccessDenied => formatter.write_str("TCP listener owner observation was denied"),
            Self::SizeRace => formatter.write_str("TCP listener table changed during observation"),
            Self::BufferLimitExceeded => {
                formatter.write_str("TCP listener table exceeds the bounded allocation")
            }
            Self::MalformedTable => formatter.write_str("TCP listener table is malformed"),
            Self::UnsupportedPlatform => {
                formatter.write_str("TCP listener ownership observation is unsupported")
            }
            Self::Windows { code } => {
                write!(
                    formatter,
                    "TCP listener owner observation failed with Win32 status {code}"
                )
            }
        }
    }
}

impl std::error::Error for TcpListenerOwnerError {}

/// Observes the unique PID owning one exact IPv4 or IPv6 localhost listener.
///
/// The result is a point-in-time OS observation. Security-sensitive callers
/// must bind it to a retained child handle/process identity before and after
/// this call.
///
/// # Errors
///
/// Returns a typed fail-closed error for invalid endpoints, missing or
/// duplicate rows, access denial, sizing races, malformed/unbounded tables,
/// unsupported platforms, and unclassified Win32 failures.
#[cfg(windows)]
pub fn observe_loopback_tcp_listener_owner(
    endpoint: SocketAddr,
) -> Result<TcpListenerOwnerObservation, TcpListenerOwnerError> {
    validate_endpoint(endpoint)?;
    let process_id = match endpoint {
        SocketAddr::V4(endpoint) => query_ipv4(*endpoint.ip(), endpoint.port())?,
        SocketAddr::V6(endpoint) => query_ipv6(*endpoint.ip(), endpoint.port())?,
    };
    Ok(TcpListenerOwnerObservation {
        endpoint,
        process_id,
    })
}

/// Off-Windows builds retain the typed API but never claim ownership.
#[cfg(not(windows))]
pub fn observe_loopback_tcp_listener_owner(
    endpoint: SocketAddr,
) -> Result<TcpListenerOwnerObservation, TcpListenerOwnerError> {
    validate_endpoint(endpoint)?;
    Err(TcpListenerOwnerError::UnsupportedPlatform)
}

fn validate_endpoint(endpoint: SocketAddr) -> Result<(), TcpListenerOwnerError> {
    let exact_loopback = match endpoint {
        SocketAddr::V4(endpoint) => *endpoint.ip() == Ipv4Addr::LOCALHOST,
        SocketAddr::V6(endpoint) => {
            *endpoint.ip() == Ipv6Addr::LOCALHOST
                && endpoint.flowinfo() == 0
                && endpoint.scope_id() == 0
        }
    };
    if !exact_loopback || endpoint.port() == 0 {
        return Err(TcpListenerOwnerError::InvalidEndpoint);
    }
    Ok(())
}

#[cfg(windows)]
fn query_ipv4(address: Ipv4Addr, port: u16) -> Result<u32, TcpListenerOwnerError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    };

    let table = query_owner_table(2)?;
    let rows = decode_rows::<MIB_TCPROW_OWNER_PID>(
        &table.words,
        table.byte_len,
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )?;
    select_ipv4_owner(&rows, address, port)
}

#[cfg(windows)]
fn select_ipv4_owner(
    rows: &[windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID],
    address: Ipv4Addr,
    port: u16,
) -> Result<u32, TcpListenerOwnerError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_LISTEN;

    let mut matches = Vec::new();
    for row in rows {
        if row.dwState != u32::try_from(MIB_TCP_STATE_LISTEN).unwrap_or(2) {
            continue;
        }
        let row_port = decode_port(row.dwLocalPort)?;
        let row_address = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        if row_address == address && row_port == port {
            matches.push(row.dwOwningPid);
        }
    }
    unique_process_id(&matches)
}

#[cfg(windows)]
fn query_ipv6(address: Ipv6Addr, port: u16) -> Result<u32, TcpListenerOwnerError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    };

    let table = query_owner_table(23)?;
    let rows = decode_rows::<MIB_TCP6ROW_OWNER_PID>(
        &table.words,
        table.byte_len,
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )?;
    select_ipv6_owner(&rows, address, port)
}

#[cfg(windows)]
fn select_ipv6_owner(
    rows: &[windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID],
    address: Ipv6Addr,
    port: u16,
) -> Result<u32, TcpListenerOwnerError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_LISTEN;

    let mut matches = Vec::new();
    for row in rows {
        if row.dwState != u32::try_from(MIB_TCP_STATE_LISTEN).unwrap_or(2) {
            continue;
        }
        let row_port = decode_port(row.dwLocalPort)?;
        let row_address = Ipv6Addr::from(row.ucLocalAddr);
        if row_address == address && row.dwLocalScopeId == 0 && row_port == port {
            matches.push(row.dwOwningPid);
        }
    }
    unique_process_id(&matches)
}

#[cfg(windows)]
fn query_owner_table(address_family: u32) -> Result<OwnerTable, TcpListenerOwnerError> {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_NOT_SUPPORTED,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };

    let mut requested = 0_u32;
    // SAFETY: the null buffer sizing call supplies a valid writable size pointer.
    let status = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &raw mut requested,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if status == ERROR_NO_DATA {
        return Err(TcpListenerOwnerError::Missing);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(classify_status(status));
    }
    let requested =
        usize::try_from(requested).map_err(|_| TcpListenerOwnerError::BufferLimitExceeded)?;
    if requested < std::mem::size_of::<u32>() {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    if requested > MAX_TCP_TABLE_BYTES {
        return Err(TcpListenerOwnerError::BufferLimitExceeded);
    }
    let word_size = std::mem::size_of::<usize>();
    let word_count = requested
        .checked_add(word_size - 1)
        .and_then(|value| value.checked_div(word_size))
        .ok_or(TcpListenerOwnerError::BufferLimitExceeded)?;
    let byte_capacity = word_count
        .checked_mul(word_size)
        .ok_or(TcpListenerOwnerError::BufferLimitExceeded)?;
    if byte_capacity > MAX_TCP_TABLE_BYTES {
        return Err(TcpListenerOwnerError::BufferLimitExceeded);
    }
    let mut buffer = vec![0_usize; word_count];
    let mut returned =
        u32::try_from(requested).map_err(|_| TcpListenerOwnerError::BufferLimitExceeded)?;
    // SAFETY: `buffer` is writable, suitably aligned, and `returned` is no
    // larger than its byte capacity. The function cannot outlive the allocation.
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast::<c_void>(),
            &raw mut returned,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if status == ERROR_INSUFFICIENT_BUFFER {
        return Err(TcpListenerOwnerError::SizeRace);
    }
    if status == ERROR_NO_DATA {
        return Err(TcpListenerOwnerError::Missing);
    }
    if status == ERROR_ACCESS_DENIED || status == ERROR_NOT_SUPPORTED || status != 0 {
        return Err(classify_status(status));
    }
    let returned = usize::try_from(returned).map_err(|_| TcpListenerOwnerError::MalformedTable)?;
    if returned < std::mem::size_of::<u32>() || returned > byte_capacity {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    Ok(OwnerTable {
        words: buffer,
        byte_len: returned,
    })
}

#[cfg(windows)]
fn classify_status(status: u32) -> TcpListenerOwnerError {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_SUPPORTED};
    match status {
        ERROR_ACCESS_DENIED => TcpListenerOwnerError::AccessDenied,
        ERROR_NOT_SUPPORTED => TcpListenerOwnerError::UnsupportedPlatform,
        code => TcpListenerOwnerError::Windows { code },
    }
}

#[cfg(windows)]
fn decode_rows<Row: Copy>(
    words: &[usize],
    byte_len: usize,
    row_offset: usize,
) -> Result<Vec<Row>, TcpListenerOwnerError> {
    let byte_capacity = words
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(TcpListenerOwnerError::MalformedTable)?;
    if byte_len > byte_capacity || byte_len < std::mem::size_of::<u32>() || row_offset > byte_len {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    let base = words.as_ptr().cast::<u8>();
    // SAFETY: the allocation is at least four bytes and `u32` is read
    // unaligned from within its initialized bounds.
    let count = unsafe { std::ptr::read_unaligned(base.cast::<u32>()) };
    let count = usize::try_from(count).map_err(|_| TcpListenerOwnerError::MalformedTable)?;
    let row_bytes = count
        .checked_mul(std::mem::size_of::<Row>())
        .ok_or(TcpListenerOwnerError::MalformedTable)?;
    let required = row_offset
        .checked_add(row_bytes)
        .ok_or(TcpListenerOwnerError::MalformedTable)?;
    if required > byte_len {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = row_offset
            .checked_add(
                index
                    .checked_mul(std::mem::size_of::<Row>())
                    .ok_or(TcpListenerOwnerError::MalformedTable)?,
            )
            .ok_or(TcpListenerOwnerError::MalformedTable)?;
        // SAFETY: `required <= byte_len` proves this complete row lies in the
        // allocation. Unaligned reads account for API table padding.
        rows.push(unsafe { std::ptr::read_unaligned(base.add(offset).cast::<Row>()) });
    }
    Ok(rows)
}

#[cfg(windows)]
fn decode_port(raw: u32) -> Result<u16, TcpListenerOwnerError> {
    if raw > u32::from(u16::MAX) {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    let port = u16::from_be(u16::try_from(raw).map_err(|_| TcpListenerOwnerError::MalformedTable)?);
    if port == 0 {
        return Err(TcpListenerOwnerError::MalformedTable);
    }
    Ok(port)
}

#[cfg(windows)]
fn unique_process_id(matches: &[u32]) -> Result<u32, TcpListenerOwnerError> {
    match matches {
        [] => Err(TcpListenerOwnerError::Missing),
        [0] => Err(TcpListenerOwnerError::MalformedTable),
        [process_id] => Ok(*process_id),
        _ => Err(TcpListenerOwnerError::Ambiguous),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_exact_localhost_and_nonzero_port() -> Result<(), Box<dyn std::error::Error>>
    {
        assert!(validate_endpoint("127.0.0.1:1".parse()?).is_ok());
        assert!(validate_endpoint("[::1]:1".parse()?).is_ok());
        assert_eq!(
            validate_endpoint("0.0.0.0:1".parse()?),
            Err(TcpListenerOwnerError::InvalidEndpoint)
        );
        assert_eq!(
            validate_endpoint("127.0.0.2:1".parse()?),
            Err(TcpListenerOwnerError::InvalidEndpoint)
        );
        assert_eq!(
            validate_endpoint("127.0.0.1:0".parse()?),
            Err(TcpListenerOwnerError::InvalidEndpoint)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn owner_selection_rejects_missing_zero_and_duplicates() {
        assert_eq!(unique_process_id(&[]), Err(TcpListenerOwnerError::Missing));
        assert_eq!(
            unique_process_id(&[0]),
            Err(TcpListenerOwnerError::MalformedTable)
        );
        assert_eq!(unique_process_id(&[7]), Ok(7));
        assert_eq!(
            unique_process_id(&[7, 7]),
            Err(TcpListenerOwnerError::Ambiguous)
        );
        assert_eq!(
            unique_process_id(&[7, 8]),
            Err(TcpListenerOwnerError::Ambiguous)
        );
    }

    #[cfg(windows)]
    #[test]
    fn malformed_row_count_and_port_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let words = vec![usize::try_from(2_u32)?];
        assert!(matches!(
            decode_rows::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID>(
                &words,
                std::mem::size_of::<usize>(),
                std::mem::size_of::<u32>(),
            ),
            Err(TcpListenerOwnerError::MalformedTable)
        ));
        assert_eq!(
            decode_port(u32::from(u16::MAX) + 1),
            Err(TcpListenerOwnerError::MalformedTable)
        );
        assert_eq!(decode_port(0), Err(TcpListenerOwnerError::MalformedTable));
        Ok(())
    }

    #[cfg(windows)]
    fn constructed_table<Row: Copy>(
        rows: &[Row],
        row_offset: usize,
    ) -> Result<(Vec<usize>, usize), std::num::TryFromIntError> {
        let byte_len = row_offset + std::mem::size_of_val(rows);
        let word_size = std::mem::size_of::<usize>();
        let word_count = byte_len.div_ceil(word_size);
        let mut words = vec![0_usize; word_count];
        let base = words.as_mut_ptr().cast::<u8>();
        // SAFETY: the allocation is word-aligned and sized for the count,
        // explicit table padding, and all complete rows written below.
        unsafe {
            std::ptr::write_unaligned(base.cast::<u32>(), u32::try_from(rows.len())?);
            for (index, row) in rows.iter().enumerate() {
                std::ptr::write_unaligned(
                    base.add(row_offset + index * std::mem::size_of::<Row>())
                        .cast::<Row>(),
                    *row,
                );
            }
        }
        Ok((words, byte_len))
    }

    #[cfg(windows)]
    fn ipv4_row(
        address: Ipv4Addr,
        port: u16,
        process_id: u32,
    ) -> Result<
        windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID,
        std::num::TryFromIntError,
    > {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCP_STATE_LISTEN, MIB_TCPROW_OWNER_PID,
        };
        // SAFETY: this Windows POD table row permits all-zero initialization;
        // every field used by the selector is assigned immediately below.
        let mut row: MIB_TCPROW_OWNER_PID = unsafe { std::mem::zeroed() };
        row.dwState = u32::try_from(MIB_TCP_STATE_LISTEN)?;
        row.dwLocalAddr = u32::from(address).to_be();
        row.dwLocalPort = u32::from(port.to_be());
        row.dwOwningPid = process_id;
        Ok(row)
    }

    #[cfg(windows)]
    #[test]
    fn constructed_ipv4_tables_cover_padding_endian_wildcard_duplicates_and_pid_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        };

        let address = Ipv4Addr::LOCALHOST;
        let port = 0x1234;
        let row_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let rows = [
            ipv4_row(Ipv4Addr::UNSPECIFIED, port, 8)?,
            ipv4_row(address, port, 41)?,
        ];
        let (words, byte_len) = constructed_table(&rows, row_offset)?;
        let decoded = decode_rows::<MIB_TCPROW_OWNER_PID>(&words, byte_len, row_offset)?;
        assert_eq!(decoded.len(), 2);
        assert_eq!(select_ipv4_owner(&decoded, address, port), Ok(41));
        assert_eq!(decode_port(decoded[1].dwLocalPort), Ok(port));

        let duplicate = [ipv4_row(address, port, 41)?, ipv4_row(address, port, 41)?];
        assert_eq!(
            select_ipv4_owner(&duplicate, address, port),
            Err(TcpListenerOwnerError::Ambiguous)
        );
        assert_eq!(
            select_ipv4_owner(&[ipv4_row(address, port, 0)?], address, port),
            Err(TcpListenerOwnerError::MalformedTable)
        );

        let mut wrong_endian = ipv4_row(address, port, 41)?;
        wrong_endian.dwLocalPort = u32::from(port);
        assert_eq!(
            select_ipv4_owner(&[wrong_endian], address, port),
            Err(TcpListenerOwnerError::Missing)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn constructed_ipv6_table_preserves_alignment_padding_and_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        };

        // SAFETY: this Windows POD row permits all-zero initialization and all
        // selector-relevant fields are assigned immediately below.
        let mut row: MIB_TCP6ROW_OWNER_PID = unsafe { std::mem::zeroed() };
        row.ucLocalAddr = Ipv6Addr::LOCALHOST.octets();
        row.dwLocalPort = u32::from(0x2345_u16.to_be());
        row.dwState = u32::try_from(MIB_TCP_STATE_LISTEN)?;
        row.dwOwningPid = 51;
        let row_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
        let (words, byte_len) = constructed_table(&[row], row_offset)?;
        let decoded = decode_rows::<MIB_TCP6ROW_OWNER_PID>(&words, byte_len, row_offset)?;
        assert_eq!(
            select_ipv6_owner(&decoded, Ipv6Addr::LOCALHOST, 0x2345),
            Ok(51)
        );
        let mut scoped = decoded[0];
        scoped.dwLocalScopeId = 1;
        assert_eq!(
            select_ipv6_owner(&[scoped], Ipv6Addr::LOCALHOST, 0x2345),
            Err(TcpListenerOwnerError::Missing)
        );
        Ok(())
    }

    #[cfg(windows)]
    fn assert_current_process_owns(
        listener: &std::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::thread::sleep;
        use std::time::{Duration, Instant};

        let endpoint = listener.local_addr()?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match observe_loopback_tcp_listener_owner(endpoint) {
                Ok(observation) => {
                    assert_eq!(observation.endpoint(), endpoint);
                    assert_eq!(observation.process_id(), std::process::id());
                    break;
                }
                Err(TcpListenerOwnerError::Missing) if Instant::now() < deadline => {
                    sleep(Duration::from_millis(10));
                }
                outcome => panic!("listener owner observation failed: {outcome:?}"),
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn current_process_owns_a_bounded_real_ipv4_loopback_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        assert_current_process_owns(&listener)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn current_process_owns_a_bounded_real_ipv6_loopback_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
        assert_current_process_owns(&listener)?;
        Ok(())
    }
}
