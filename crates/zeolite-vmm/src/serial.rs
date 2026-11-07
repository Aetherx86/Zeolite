//! Minimal 16550A UART: enough for the Linux 8250 driver and for raw guest payloads.
//!
//! Output is captured into a bounded buffer. Receive is not implemented, so the guest
//! always sees an empty receive register.

const IER_THRE: u8 = 0x02;
const IIR_NONE: u8 = 0x01;
const IIR_THRE: u8 = 0x02;
const IIR_FIFO_ENABLED: u8 = 0xC0;
const LCR_DLAB: u8 = 0x80;
const LSR_TX_EMPTY: u8 = 0x60;
const MSR_CONNECTED: u8 = 0xB0;

pub struct Serial {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    dll: u8,
    dlm: u8,
    thre_pending: bool,
    irq_requested: bool,
    output: Vec<u8>,
    max_output: usize,
    truncated: bool,
}

impl Serial {
    pub fn new(max_output: usize) -> Self {
        Serial {
            ier: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            dll: 12,
            dlm: 0,
            thre_pending: false,
            irq_requested: false,
            output: Vec::new(),
            max_output,
            truncated: false,
        }
    }

    /// Reads the register at `offset`, which must be in `0..8`.
    pub fn read(&mut self, offset: u16) -> u8 {
        let dlab = self.lcr & LCR_DLAB != 0;
        match offset {
            0 if dlab => self.dll,
            0 => 0,
            1 if dlab => self.dlm,
            1 => self.ier,
            2 => {
                if self.thre_pending {
                    // Reading the identification register acknowledges a THRE interrupt.
                    self.thre_pending = false;
                    IIR_THRE | IIR_FIFO_ENABLED
                } else {
                    IIR_NONE | IIR_FIFO_ENABLED
                }
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => LSR_TX_EMPTY,
            6 => MSR_CONNECTED,
            7 => self.scr,
            _ => 0xFF,
        }
    }

    /// Writes the register at `offset`, which must be in `0..8`.
    pub fn write(&mut self, offset: u16, value: u8) {
        let dlab = self.lcr & LCR_DLAB != 0;
        match offset {
            0 if dlab => self.dll = value,
            0 => {
                self.push_output(value);
                self.raise_thre();
            }
            1 if dlab => self.dlm = value,
            1 => {
                let enabled_now = value & IER_THRE != 0 && self.ier & IER_THRE == 0;
                self.ier = value;
                // A driver enabling this interrupt expects it at once if the transmitter
                // is empty, which it always is here.
                if enabled_now {
                    self.raise_thre();
                }
            }
            3 => self.lcr = value,
            4 => self.mcr = value,
            7 => self.scr = value,
            _ => {}
        }
    }

    fn raise_thre(&mut self) {
        if self.ier & IER_THRE != 0 {
            self.thre_pending = true;
            self.irq_requested = true;
        }
    }

    fn push_output(&mut self, byte: u8) {
        if self.output.len() < self.max_output {
            self.output.push(byte);
        } else {
            self.truncated = true;
        }
    }

    /// Returns whether an interrupt should be delivered, clearing the request.
    pub fn take_irq(&mut self) -> bool {
        std::mem::take(&mut self.irq_requested)
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }

    pub fn into_output(self) -> Vec<u8> {
        self.output
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_transmitted_bytes() {
        let mut s = Serial::new(16);
        for b in b"hi" {
            s.write(0, *b);
        }
        assert_eq!(s.output(), b"hi");
    }

    #[test]
    fn output_is_bounded() {
        let mut s = Serial::new(2);
        for b in b"hello" {
            s.write(0, *b);
        }
        assert_eq!(s.output(), b"he");
        assert!(s.truncated());
    }

    #[test]
    fn dlab_redirects_the_low_registers() {
        let mut s = Serial::new(16);
        s.write(3, LCR_DLAB);
        s.write(0, 0x34);
        s.write(1, 0x12);
        assert_eq!((s.read(0), s.read(1)), (0x34, 0x12));
        assert!(s.output().is_empty(), "divisor writes are not transmitted");
        s.write(3, 0x03);
        assert_eq!(s.read(1), 0, "IER is visible again and still clear");
    }

    #[test]
    fn scratch_register_round_trips_for_uart_detection() {
        let mut s = Serial::new(16);
        s.write(7, 0x5A);
        assert_eq!(s.read(7), 0x5A);
    }

    #[test]
    fn line_status_always_reports_an_empty_transmitter() {
        let mut s = Serial::new(16);
        assert_eq!(s.read(5) & LSR_TX_EMPTY, LSR_TX_EMPTY);
        assert_eq!(s.read(5) & 0x01, 0, "the receive buffer is always empty");
    }

    #[test]
    fn thre_interrupt_follows_the_8250_protocol() {
        let mut s = Serial::new(16);
        s.write(0, b'a');
        assert!(!s.take_irq(), "no interrupt while disabled");
        assert_eq!(s.read(2) & 0x0F, IIR_NONE);

        s.write(1, IER_THRE);
        assert!(
            s.take_irq(),
            "enabling with an empty transmitter fires at once"
        );
        assert!(!s.take_irq(), "the request is consumed");
        assert_eq!(s.read(2) & 0x0F, IIR_THRE);
        assert_eq!(s.read(2) & 0x0F, IIR_NONE, "reading IIR acknowledges it");

        s.write(0, b'b');
        assert!(s.take_irq());
        assert_eq!(s.read(2) & 0x0F, IIR_THRE);
    }
}
