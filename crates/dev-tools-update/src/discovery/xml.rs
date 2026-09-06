//! Bounded, inert XML events shared by metadata adapters.
use super::{DiscoveryError, PAGE_LIMIT};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::XmlVersion;
use std::borrow::Cow;
use std::collections::BTreeSet;

pub(super) enum XmlEvent<'input> {
    Start {
        namespace: String,
        name: String,
        attributes: Vec<XmlAttribute>,
    },
    End,
    Text(Cow<'input, str>),
}

pub(super) struct XmlAttribute {
    pub namespace: String,
    pub name: String,
    pub value: String,
}

pub(super) struct XmlReader<'input> {
    reader: NsReader<&'input [u8]>,
    depth: usize,
    events: usize,
    root_seen: bool,
    finished: bool,
}

impl<'input> XmlReader<'input> {
    pub fn new(text: &'input str) -> Result<Self, DiscoveryError> {
        if text.len() > PAGE_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        validate_xml_text(text)?;
        let mut reader = NsReader::from_str(text);
        reader.config_mut().enable_all_checks(true);
        reader.config_mut().expand_empty_elements = true;
        reader.resolver_mut().set_max_namespace_bindings(64);
        Ok(Self {
            reader,
            depth: 0,
            events: 0,
            root_seen: false,
            finished: false,
        })
    }

    pub fn next(&mut self) -> Result<Option<XmlEvent<'input>>, DiscoveryError> {
        if self.finished {
            return Ok(None);
        }
        loop {
            if self.events >= 16_384 {
                return Err(DiscoveryError::InventoryLimit);
            }
            self.events += 1;
            let event = self
                .reader
                .read_event()
                .map_err(|_| DiscoveryError::InvalidMetadata)?;
            match event {
                Event::Start(start) => {
                    if self.depth >= 64 {
                        return Err(DiscoveryError::InventoryLimit);
                    }
                    if !valid_qname(start.name().as_ref()) || (self.depth == 0 && self.root_seen) {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    self.root_seen = true;
                    self.depth += 1;
                    let (namespace, local) = self.reader.resolver().resolve_element(start.name());
                    let namespace = namespace_text(namespace)?.to_owned();
                    let name = local.as_ref().to_owned();
                    let mut attributes = BTreeSet::new();
                    let mut values = Vec::new();
                    for (index, attr) in start.attributes().enumerate() {
                        if index >= 64 {
                            return Err(DiscoveryError::InventoryLimit);
                        }
                        let attr = attr.map_err(|_| DiscoveryError::InvalidMetadata)?;
                        if !valid_qname(attr.key.as_ref()) || attr.value.contains('<') {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                        let value = attr
                            .normalized_value(XmlVersion::Implicit1_0)
                            .map_err(|_| DiscoveryError::InvalidMetadata)?;
                        validate_xml_text(&value)?;
                        if attr.key.as_namespace_binding().is_none() {
                            let (ns, key) = self.reader.resolver().resolve_attribute(attr.key);
                            let ns = namespace_text(ns)?;
                            if !attributes.insert((ns.to_owned(), key.as_ref().to_owned())) {
                                return Err(DiscoveryError::InvalidMetadata);
                            }
                            values.push(XmlAttribute {
                                namespace: ns.to_owned(),
                                name: key.as_ref().to_owned(),
                                value: value.into_owned(),
                            });
                        }
                    }
                    return Ok(Some(XmlEvent::Start {
                        namespace,
                        name,
                        attributes: values,
                    }));
                }
                Event::End(_) => {
                    self.depth = self
                        .depth
                        .checked_sub(1)
                        .ok_or(DiscoveryError::InvalidMetadata)?;
                    return Ok(Some(XmlEvent::End));
                }
                Event::Text(value) => {
                    if value.as_ref().contains("]]>") {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    let text = value.xml10_content();
                    validate_xml_text(&text)?;
                    if self.depth == 0 {
                        if !text.trim().is_empty() {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                    } else {
                        return Ok(Some(XmlEvent::Text(text)));
                    }
                }
                Event::CData(value) => {
                    if self.depth == 0 {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    let text = value.xml10_content();
                    validate_xml_text(&text)?;
                    return Ok(Some(XmlEvent::Text(text)));
                }
                Event::GeneralRef(value) => {
                    if self.depth == 0 {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    let character = match value
                        .resolve_char_ref()
                        .map_err(|_| DiscoveryError::InvalidMetadata)?
                    {
                        Some(value) => value,
                        None => match value.as_ref() {
                            "amp" => '&',
                            "lt" => '<',
                            "gt" => '>',
                            "apos" => '\'',
                            "quot" => '"',
                            _ => return Err(DiscoveryError::InvalidMetadata),
                        },
                    };
                    let text = character.to_string();
                    validate_xml_text(&text)?;
                    return Ok(Some(XmlEvent::Text(Cow::Owned(text))));
                }
                Event::Decl(declaration) => {
                    if self.events != 1
                        || self.root_seen
                        || declaration
                            .version()
                            .map_err(|_| DiscoveryError::InvalidMetadata)?
                            != "1.0"
                    {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    let start =
                        quick_xml::events::BytesStart::from_content(declaration.as_ref(), 3);
                    for (index, attribute) in start.attributes().enumerate() {
                        let attribute = attribute.map_err(|_| DiscoveryError::InvalidMetadata)?;
                        match attribute.key.as_ref() {
                            "version" if index == 0 => {}
                            "encoding" if index == 1 => {}
                            "standalone"
                                if matches!(index, 1 | 2)
                                    && matches!(attribute.value.as_ref(), "yes" | "no") => {}
                            _ => return Err(DiscoveryError::InvalidMetadata),
                        }
                    }
                    if let Some(encoding) = declaration.encoding() {
                        if !encoding
                            .map_err(|_| DiscoveryError::InvalidMetadata)?
                            .eq_ignore_ascii_case("UTF-8")
                        {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                    }
                }
                Event::Comment(_) => {}
                Event::Eof => {
                    if !self.root_seen || self.depth != 0 {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    self.finished = true;
                    return Ok(None);
                }
                Event::DocType(_) | Event::PI(_) | Event::Empty(_) => {
                    return Err(DiscoveryError::InvalidMetadata)
                }
            }
        }
    }
}

fn namespace_text(namespace: ResolveResult<'_>) -> Result<&str, DiscoveryError> {
    match namespace {
        ResolveResult::Unbound => Ok(""),
        ResolveResult::Bound(value) => Ok(value.0),
        ResolveResult::Unknown(_) => Err(DiscoveryError::InvalidMetadata),
    }
}

fn valid_qname(name: &str) -> bool {
    name.len() <= 128
        && name.split(':').count() <= 2
        && name.split(':').all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}

fn validate_xml_text(text: &str) -> Result<(), DiscoveryError> {
    if text.chars().any(|c| {
        (c < ' ' && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{fffe}' | '\u{ffff}')
    }) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(())
}
