use smallvec::SmallVec;
use tl_proto::*;

pub type HashRef<'a> = &'a [u8; 32];

#[derive(Debug, Clone)]
pub struct OutgoingPacketContents<'tl> {
    /// 7 or 3 random bytes
    pub rand1: &'tl [u8],
    pub from: Option<PublicKey<'tl>>,
    pub messages: SmallVec<[Message<'tl>; 4]>,
    pub address: AddressList<'tl>,
    pub seqno: u64,
    pub confirm_seqno: u64,
    pub reinit_dates: Option<(u32, u32)>,
    /// 3 or 7 random bytes
    pub rand2: &'tl [u8],
}

impl<'tl> TlWrite for OutgoingPacketContents<'tl> {
    fn max_size_hint(&self) -> usize {
        let messages_size = match self.messages.first() {
            Some(message) if self.messages.len() == 1 => message.max_size_hint(),
            _ => self.messages.max_size_hint(),
        };

        8 // rand1 (1 byte length, 7 bytes data)
        + 4 // flags
        + self.from.max_size_hint()
        + messages_size
        + self.address.max_size_hint()
        + 8 // seqno
        + 8 // confirm_seqno
        + self.reinit_dates.max_size_hint()
        + 4 // rand2 (1 byte length, 3 bytes data)
    }

    fn write_to<P>(&self, packet: &mut P)
    where
        P: TlPacket,
    {
        const DEFAULT_FLAGS: u32 = (0b1 << 4) | (0b1 << 6) | (0b1 << 7);

        let flags = DEFAULT_FLAGS
            | (self.from.is_some() as u32)
            | (if self.messages.len() == 1 {
                0b1 << 2
            } else {
                0b1 << 3
            } | ((self.reinit_dates.is_some() as u32) << 10));

        packet.write_u32(0xd142cd89); // constructor
        self.rand1.write_to(packet);
        packet.write_u32(flags);
        match self.messages.first() {
            Some(message) if self.messages.len() == 1 => message.write_to(packet),
            _ => self.messages.write_to(packet),
        }
        self.address.write_to(packet);
        self.seqno.write_to(packet);
        self.confirm_seqno.write_to(packet);
        self.reinit_dates.write_to(packet);
        self.rand2.write_to(packet);
    }
}

#[derive(Debug, Clone)]
pub struct IncomingPacketContents<'tl> {
    pub from: Option<PublicKey<'tl>>,

    pub messages: SmallVec<[Message<'tl>; 4]>,
    pub address: Option<AddressList<'tl>>,

    pub seqno: Option<u64>,
    pub confirm_seqno: Option<u64>,

    pub reinit_dates: Option<(u32, u32)>,
}

impl<'tl> TlRead<'tl> for IncomingPacketContents<'tl> {
    fn read_from(packet: &'tl [u8], offset: &mut usize) -> TlResult<Self> {
        #[inline(always)]
        fn read_optional<'tl, T: TlRead<'tl>, const N: usize>(
            flags: u32,
            packet: &'tl [u8],
            offset: &mut usize,
        ) -> TlResult<Option<T>> {
            Ok(if flags & (0b1 << N) != 0 {
                Some(T::read_from(packet, offset)?)
            } else {
                None
            })
        }

        if u32::read_from(packet, offset)? != 0xd142cd89 {
            return Err(TlError::UnknownConstructor);
        }

        <&[u8] as TlRead>::read_from(packet, offset)?; // rand1

        let flags = u32::read_from(packet, offset)?;
        let from = read_optional::<PublicKey, 0>(flags, packet, offset)?;
        read_optional::<HashRef, 1>(flags, packet, offset)?; // from_short

        let message = read_optional::<Message, 2>(flags, packet, offset)?;
        let messages = read_optional::<SmallVec<[Message<'tl>; 4]>, 3>(flags, packet, offset)?;

        let address = read_optional::<AddressList, 4>(flags, packet, offset)?;
        read_optional::<AddressList, 5>(flags, packet, offset)?; // priority_address

        let seqno = read_optional::<u64, 6>(flags, packet, offset)?;
        let confirm_seqno = read_optional::<u64, 7>(flags, packet, offset)?;

        read_optional::<u32, 8>(flags, packet, offset)?; // recv_addr_list_version
        read_optional::<u32, 9>(flags, packet, offset)?; // recv_priority_addr_list_version

        let reinit_dates = read_optional::<(u32, u32), 10>(flags, packet, offset)?;

        read_optional::<&[u8], 11>(flags, packet, offset)?; // signature
        <&[u8] as TlRead>::read_from(packet, offset)?; // rand2

        Ok(Self {
            from,
            messages: match (messages, message) {
                (Some(messages), None) => messages,
                (None, Some(message)) => {
                    let mut messages = SmallVec::with_capacity(1);
                    messages.push(message);
                    messages
                }
                (Some(mut messages), Some(message)) => {
                    messages.insert(0, message);
                    messages
                }
                (None, None) => return Err(TlError::UnexpectedEof),
            },
            address,
            seqno,
            confirm_seqno,
            reinit_dates,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AddressList<'tl> {
    pub address: Option<Address<'tl>>,
    pub version: u32,
    pub reinit_date: u32,
    pub priority: u32,
    pub expire_at: u32,
}

impl<'tl> TlRead<'tl> for AddressList<'tl> {
    fn read_from(packet: &'tl [u8], offset: &mut usize) -> TlResult<Self> {
        let address_count = u32::read_from(packet, offset)?;
        let mut address = None;
        for _ in 0..address_count {
            let item = Address::read_from(packet, offset)?;
            if address.is_none() {
                address = Some(item);
            }
        }

        let version = u32::read_from(packet, offset)?;
        let reinit_date = u32::read_from(packet, offset)?;
        let priority = u32::read_from(packet, offset)?;
        let expire_at = u32::read_from(packet, offset)?;

        Ok(Self {
            address,
            version,
            reinit_date,
            priority,
            expire_at,
        })
    }
}

impl TlWrite for AddressList<'_> {
    fn max_size_hint(&self) -> usize {
        // 4 bytes - address vector size
        // optional address size
        // 4 bytes - version
        // 4 bytes - reinit_date
        // 4 bytes - priority
        // 4 bytes - expire_at
        20 + self.address.max_size_hint()
    }

    fn write_to<P>(&self, packet: &mut P)
    where
        P: TlPacket,
    {
        u32::write_to(&(self.address.is_some() as u32), packet);
        self.address.write_to(packet);
        self.version.write_to(packet);
        self.reinit_date.write_to(packet);
        self.priority.write_to(packet);
        self.expire_at.write_to(packet);
    }
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum Address<'tl> {
    #[tl(id = 0x670da6e7, size_hint = 8)]
    Udp { ip: u32, port: u32 },
    #[tl(id = 0xe31d63fa, size_hint = 20)]
    Udp6 { ip: &'tl [u8; 16], port: u32 },
    #[tl(id = 0x092b02eb)]
    Tunnel {
        to: HashRef<'tl>,
        pubkey: PublicKey<'tl>,
    },
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum PublicKey<'tl> {
    #[tl(id = 0x4813b4c6, size_hint = 32)]
    Ed25519 { key: HashRef<'tl> },
    #[tl(id = 0x34ba45cb)]
    Overlay { name: &'tl [u8] },
    #[tl(id = 0x2dbcadd4, size_hint = 32)]
    Aes { key: HashRef<'tl> },
    #[tl(id = 0xb61f450a)]
    Unencoded { data: &'tl [u8] },
}

#[derive(Debug, Copy, Clone, TlRead, TlWrite)]
#[tl(boxed)]
pub enum Message<'tl> {
    #[tl(id = 0x0fac8416)]
    Answer {
        query_id: HashRef<'tl>,
        answer: &'tl [u8],
    },
    #[tl(id = 0x60dd1d69, size_hint = 68)]
    ConfirmChannel {
        key: HashRef<'tl>,
        peer_key: HashRef<'tl>,
        date: u32,
    },
    #[tl(id = 0xe673c3bb, size_hint = 36)]
    CreateChannel { key: HashRef<'tl>, date: u32 },
    #[tl(id = 0x204818f5)]
    Custom { data: &'tl [u8] },
    #[tl(id = 0x17f8dfda)]
    Nop,
    #[tl(id = 0xfd452d39)]
    Part {
        hash: HashRef<'tl>,
        total_size: u32,
        offset: u32,
        data: &'tl [u8],
    },
    #[tl(id = 0xb48bf97a)]
    Query {
        query_id: HashRef<'tl>,
        query: &'tl [u8],
    },
    #[tl(id = 0x10c20520, size_hint = 4)]
    Reinit { date: u32 },
}
