//! TEMP probe: dump every packet WinDivert delivers (admin required).
//! Prints to console AND appends to %TEMP%\\dnsprobe.log. Waits for Enter before exit.
use libloading::{Library, Symbol};
use std::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

type OpenFn = unsafe extern "system" fn(*const i8, u32, i32, u64) -> *mut c_void;
type RecvFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u8, *mut u32) -> i32;
type SendFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *const u8, *mut u32) -> i32;
type CloseFn = unsafe extern "system" fn(*mut c_void);

fn main() {
    let log_path = std::env::temp_dir().join("dnsprobe.log");
    let _ = std::fs::remove_file(&log_path);
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();
    use std::io::Write;
    let mut say = |s: String| { println!("{s}"); let _ = writeln!(log, "{s}"); };
    say("=== dnsprobe start ===".to_string());
    let lib = match unsafe { Library::new("WinDivert.dll") } { Ok(l) => l, Err(e) => { say(format!("DLL LOAD FAIL: {e}")); wait(); return; } };
    let open: Symbol<OpenFn> = match unsafe { lib.get(b"WinDivertOpen") } { Ok(s) => s, Err(e) => { say(format!("symbol Open FAIL: {e}")); wait(); return; } };
    let recv: Symbol<RecvFn> = match unsafe { lib.get(b"WinDivertRecv") } { Ok(s) => s, Err(e) => { say(format!("symbol Recv FAIL: {e}")); wait(); return; } };
    let send: Symbol<SendFn> = match unsafe { lib.get(b"WinDivertSend") } { Ok(s) => s, Err(e) => { say(format!("symbol Send FAIL: {e}")); wait(); return; } };
    let close: Symbol<CloseFn> = match unsafe { lib.get(b"WinDivertClose") } { Ok(s) => s, Err(e) => { say(format!("symbol Close FAIL: {e}")); wait(); return; } };
    let filter = std::ffi::CString::new("udp.DstPort == 53").unwrap();
    let h = unsafe { open(filter.as_ptr(), 0, 0, 0) };
    if h.is_null() || (h as isize) == -1 {
        let err = unsafe { GetLastError() };
        say(format!("OPEN FAILED GetLastError={err:#x} (need admin / driver not loaded)"));
        wait();
        return;
    }
    say("OPEN OK. Sniffing udp.DstPort==53 ... window stays open.".to_string());
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 65535];
    let mut addr = vec![0u8; 64];
    let mut len: u32 = 0;
    let mut count = 0u32;
    let mut recv_fail = 0u32;
    while start.elapsed().as_secs() < 60 && count < 200 {
        let ok = unsafe { recv(h, buf.as_mut_ptr(), buf.len() as u32, addr.as_mut_ptr(), &mut len) };
        if ok == 0 {
            recv_fail += 1;
            let e = unsafe { GetLastError() };
            say(format!("RECV FAIL #{recv_fail} GetLastError={e:#x}"));
            std::thread::sleep(std::time::Duration::from_millis(200));
            if recv_fail > 3 { break; }
            continue;
        }
        let n = len as usize;
        count += 1;
        if n == 0 { continue; }
        let ver = buf[0] >> 4;
        let mut proto = 0u8;
        let mut dst = 0u16;
        let mut qname = String::new();
        if ver == 4 {
            let ihl = ((buf[0] & 0x0f) as usize) * 4;
            if n >= ihl + 8 {
                proto = buf[9];
                dst = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
                if proto == 17 && n >= ihl + 8 + 12 && buf[ihl + 8 + 2] & 0x80 == 0 {
                    let mut i = ihl + 8 + 12;
                    let mut labels = Vec::new();
                    while i < n { let l = buf[i] as usize; if l == 0 { break; } i += 1; if i + l > n { break; } labels.push(String::from_utf8_lossy(&buf[i..i+l]).to_string()); i += l; }
                    qname = labels.join(".");
                }
            }
        } else if ver == 6 {
            if n >= 8 { proto = buf[6]; }
        }
        say(format!("PACK#{} v{} proto={} len={} dstPort={} qname={} addr[8..12]={:02x} {:02x} {:02x} {:02x}",
            count, ver, proto, n, dst, if qname.is_empty() { "-".to_string() } else { qname }, addr[8], addr[9], addr[10], addr[11]));
        unsafe {
            let mut sent: u32 = 0;
            let r = send(h, buf.as_ptr(), len, addr.as_ptr(), &mut sent);
            if r == 0 { say(format!("SEND FAIL error={:#x}", GetLastError())); }
        }
    }
    unsafe { close(h) };
    say(format!("DONE. total packets: {count}, recv_fail: {recv_fail}. Log: {}", log_path.display()));
    say("Press Enter to exit.".to_string());
    wait();
}

fn wait() {
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}