use std::{
    fmt::{Debug, Display},
    io::Cursor,
    os::fd::OwnedFd,
};

use derive_more::derive::{Deref, DerefMut, Display};
use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};
use simd_json::{owned::Object, OwnedValue, StaticNode};
use simdnbt::owned::{NbtCompound, NbtList, NbtTag};

use crate::identifier::Identifier;

#[derive(Encode, Decode)]
pub struct RegistryDataS2c {
    pub id: Identifier,
    pub entries: Vec<(Identifier, Option<Nbt>)>,
}

impl Debug for RegistryDataS2c {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&simd_json::to_string_pretty(&self.to_json()).unwrap())?;
        Ok(())
    }
}

impl RegistryDataS2c {
    pub fn to_json(&self) -> OwnedValue {
        let mut obj = Object::new();
        obj.insert("id".to_string(), OwnedValue::from(self.id.to_string()));
        obj.insert(
            "entries".to_string(),
            OwnedValue::Array(
                self.entries
                    .iter()
                    .map(|entry| {
                        let mut obj = Object::new();
                        obj.insert("id".to_string(), OwnedValue::from(entry.0.to_string()));
                        if let Some(nbt) = &entry.1 {
                            obj.insert("entry".to_string(), nbt.to_json());
                        }
                        obj.into()
                    })
                    .collect::<Vec<_>>(),
            ),
        );
        let value: OwnedValue = obj.into();
        value
    }
}

#[derive(Deref, DerefMut)]
pub struct Nbt(pub simdnbt::owned::NbtCompound);

impl Debug for Nbt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&simd_json::to_string_pretty(&self.to_json()).unwrap())?;
        Ok(())
    }
}

impl Encode for Nbt {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        let mut vec = Vec::new();
        self.write(&mut vec);
        buf.try_write(&[0x0a])?;
        buf.try_write(vec.as_slice())?;
        Ok(())
    }
}

impl Decode for Nbt {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let type_id = buf.read(1);
        if type_id.is_empty() {
            Err(())?
        }
        let type_id = type_id[0];
        if type_id != 0x0a {
            Err(())?
        }
        let mut cur = Cursor::new(buf.get_continuous(buf.remaining()));
        let nbt = simdnbt::owned::read_compound(&mut cur).map_err(|_| ())?;
        buf.advance(cur.position() as usize);
        Ok(Nbt(nbt))
    }
}

impl Nbt {
    pub fn to_json(&self) -> OwnedValue {
        let mut obj = Object::new();
        nbt_compuond_to_json_object(&self.0, &mut obj);
        let value: OwnedValue = obj.into();
        value
    }
}

fn nbt_compuond_to_json_object(nbt: &NbtCompound, obj: &mut Object) {
    for ele in nbt.iter() {
        obj.insert(ele.0.to_string(), nbt_tag_to_json_value(&ele.1));
    }
}

fn nbt_tag_to_json_value(nbt: &NbtTag) -> OwnedValue {
    match nbt {
        NbtTag::Byte(v) => OwnedValue::Static(StaticNode::U64(*v as u64)),
        NbtTag::Short(v) => OwnedValue::Static(StaticNode::I64(*v as i64)),
        NbtTag::Int(v) => OwnedValue::Static(StaticNode::I64(*v as i64)),
        NbtTag::Long(v) => OwnedValue::Static(StaticNode::I64(*v as i64)),
        NbtTag::Float(v) => OwnedValue::Static(StaticNode::F64(*v as f64)),
        NbtTag::Double(v) => OwnedValue::Static(StaticNode::F64(*v as f64)),
        NbtTag::ByteArray(v) => OwnedValue::from(v.clone()),
        NbtTag::String(v) => OwnedValue::from(v.to_str()),
        NbtTag::List(v) => nbt_list_to_json_value(&v),
        NbtTag::Compound(v) => {
            let mut obj = Object::with_capacity(v.len());
            nbt_compuond_to_json_object(v, &mut obj);
            obj.into()
        }
        NbtTag::IntArray(v) => OwnedValue::Array(
            v.iter()
                .map(|v| OwnedValue::Static(StaticNode::I64(*v as i64)))
                .collect(),
        ),
        NbtTag::LongArray(v) => OwnedValue::Array(
            v.iter()
                .map(|v| OwnedValue::Static(StaticNode::I64(*v as i64)))
                .collect(),
        ),
    }
}

fn nbt_list_to_json_value(nbt_list: &NbtList) -> OwnedValue {
    match nbt_list {
        simdnbt::owned::NbtList::Empty => OwnedValue::Array(vec![]),
        simdnbt::owned::NbtList::Byte(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::U64(*v as u64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::Short(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::I64(*v as i64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::Int(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::I64(*v as i64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::Long(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::I64(*v as i64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::Float(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::F64(*v as f64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::Double(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| OwnedValue::Static(StaticNode::F64(*v as f64)))
                .collect(),
        ),
        simdnbt::owned::NbtList::ByteArray(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| v.iter().map(|v| OwnedValue::from(*v)).collect())
                .collect(),
        ),
        simdnbt::owned::NbtList::String(vec) => {
            OwnedValue::Array(vec.iter().map(|v| OwnedValue::from(v.to_str())).collect())
        }
        simdnbt::owned::NbtList::List(vec) => {
            OwnedValue::Array(vec.iter().map(|v| nbt_list_to_json_value(&v)).collect())
        }
        simdnbt::owned::NbtList::Compound(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| {
                    let mut obj = Object::with_capacity(v.len());
                    nbt_compuond_to_json_object(&v, &mut obj);
                    obj.into()
                })
                .collect(),
        ),
        simdnbt::owned::NbtList::IntArray(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| v.iter().map(|v| OwnedValue::from(*v)).collect())
                .collect(),
        ),
        simdnbt::owned::NbtList::LongArray(vec) => OwnedValue::Array(
            vec.iter()
                .map(|v| v.iter().map(|v| OwnedValue::from(*v)).collect())
                .collect(),
        ),
    }
}
