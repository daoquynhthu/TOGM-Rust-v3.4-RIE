use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactsError {
    NotFound,
    AlreadyExists,
    InvalidFormat,
    StorageError,
}

impl fmt::Display for ContactsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactsError::NotFound => write!(f, "Contact not found"),
            ContactsError::AlreadyExists => write!(f, "Contact already exists"),
            ContactsError::InvalidFormat => write!(f, "Invalid contact format"),
            ContactsError::StorageError => write!(f, "Storage error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContactsError {}

pub struct Contact {
    pub id: Vec<u8>,
    pub name: Vec<u8>,
}

pub struct ContactsManager {
    contacts: Vec<Contact>,
}

impl ContactsManager {
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
        }
    }

    pub fn add_contact(&mut self, contact: Contact) -> Result<(), ContactsError> {
        if self.contacts.iter().any(|c| c.id == contact.id) {
            return Err(ContactsError::AlreadyExists);
        }
        self.contacts.push(contact);
        Ok(())
    }

    pub fn get_contact(&self, id: &[u8]) -> Result<&Contact, ContactsError> {
        self.contacts.iter().find(|c| c.id == id).ok_or(ContactsError::NotFound)
    }
}
