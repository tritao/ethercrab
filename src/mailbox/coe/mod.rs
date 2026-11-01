mod abort_code;
mod headers;
pub mod services;

use crate::{
    ObjectDescriptionListQuery, ObjectDescriptionListQueryCounts, SubDevice, SubDeviceRef,
    error::{Error, Item, MailboxError, PduError},
    fmt,
    mailbox::{
        MailboxHeader, MailboxType,
        coe::{
            self,
            services::{
                CoeServiceRequest, ObjectDescriptionListRequest, ObjectDescriptionListResponse,
                SdoExpedited, SdoNormal, SdoSegmented,
            },
        },
    },
    pdu_loop::ReceivedPdu,
    register::RegisterAddress,
    subdevice::Mailbox,
    timer_factory::IntoTimeout,
};
use core::ops::Deref;
use core::{any::type_name, fmt::Debug};
use ethercrab_wire::{
    EtherCrabWireRead, EtherCrabWireReadSized, EtherCrabWireSized, EtherCrabWireWrite,
    EtherCrabWireWriteSized,
};

pub(crate) use headers::{CoeCommand, CoeHeader, CoeService, SdoExpeditedPayload, SdoInfoOpCode};

pub use abort_code::CoeAbortCode;
pub use headers::SubIndex;

/// A CANopen emergency received through a SubDevice's CoE mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Emergency {
    /// CANopen emergency error code.
    pub error_code: u16,
    /// CANopen error register.
    pub error_register: u8,
    /// Manufacturer-specific information.
    pub data: [u8; 5],
}

impl Emergency {
    /// Decode an emergency from a complete mailbox message, including its mailbox header.
    pub fn from_mailbox(bytes: &[u8]) -> Option<Self> {
        let header = MailboxHeader::unpack_from_slice(bytes).ok()?;
        let coe = CoeHeader::unpack_from_slice(bytes.get(6..)?).ok()?;
        if header.mailbox_type != MailboxType::Coe
            || coe.service != CoeService::Emergency
            || header.length < 10
        {
            return None;
        }
        let data = bytes.get(8..16)?;
        Some(Self {
            error_code: u16::from_le_bytes([data[0], data[1]]),
            error_register: data[2],
            data: data[3..8].try_into().ok()?,
        })
    }
}

fn save_unsolicited(subdevice: &SubDevice, response: &[u8]) -> Result<(), Error> {
    let header = MailboxHeader::unpack_from_slice(response)?;
    let end = usize::from(header.length) + MailboxHeader::PACKED_LEN;
    let data = response.get(..end).ok_or(Error::Pdu(PduError::Decode))?;
    #[cfg(not(feature = "std"))]
    let message = crate::subdevice::UnsolicitedMailbox::from_slice(data)
        .map_err(|_| Error::Capacity(Item::UnsolicitedMailbox))?;
    #[cfg(feature = "std")]
    let message = data.to_vec();
    subdevice
        .unsolicited_mailboxes
        .write()
        .push_back(message)
        .map_err(|_| Error::Capacity(Item::UnsolicitedMailbox))
}

// Return true only for a response to be processed by the SDO transaction.
fn route_sdo_response(subdevice: &SubDevice, response: &[u8]) -> Result<bool, Error> {
    let is_sdo_response = response.get(5).is_some_and(|b| b & 0x0f == 3)
        && response.get(7).is_some_and(|b| b >> 4 == 3);
    if !is_sdo_response {
        save_unsolicited(subdevice, response)?;
    }
    Ok(is_sdo_response)
}

fn append_upload_segment(
    buf: &mut [u8],
    total_len: &mut usize,
    headers: &SdoSegmented,
    data: &[u8],
) -> Result<(), Error> {
    let mut chunk_len = usize::from(
        headers
            .header
            .length
            .checked_sub(3)
            .ok_or(Error::Internal)?,
    );
    // The minimum segment data field is seven bytes; the command says how
    // many bytes of that field are padding on the last, short segment.
    if chunk_len == 7 {
        chunk_len = chunk_len
            .checked_sub(usize::from(headers.sdo_header.segment_data_size))
            .ok_or(Error::Internal)?;
    }
    let end = total_len.checked_add(chunk_len).ok_or(Error::Internal)?;
    let source = data.get(..chunk_len).ok_or(Error::Internal)?;
    buf.get_mut(*total_len..end)
        .ok_or(Error::Internal)?
        .copy_from_slice(source);
    *total_len = end;
    Ok(())
}

#[cfg(test)]
mod emergency_tests {
    use super::*;

    #[test]
    fn emergency_uses_coe_payload_offset_and_keeps_manufacturer_data() {
        let frame = [10, 0, 0, 0, 0, 3, 0, 0x10, 0x10, 0x32, 4, 1, 2, 3, 4, 5];
        assert_eq!(
            Emergency::from_mailbox(&frame),
            Some(Emergency {
                error_code: 0x3210,
                error_register: 4,
                data: [1, 2, 3, 4, 5],
            })
        );
        assert_eq!(Emergency::from_mailbox(&frame[..15]), None);
    }

    #[test]
    fn upload_segment_response_has_a_nine_byte_header() {
        // A last segment with four bytes and three unused bytes.
        let frame = [10, 0, 0, 0, 0, 0x13, 0, 0x30, 0x07, 0x92, 1, 2, 0, 0, 0, 0];
        let header = SdoSegmented::unpack_from_slice(&frame).unwrap();
        assert_eq!(header.sdo_header.command, CoeCommand::UploadSegmentResponse);
        assert!(header.sdo_header.is_last_segment);
        assert_eq!(header.sdo_header.segment_data_size, 3);
        assert_eq!(
            &frame[SdoSegmented::RESPONSE_DATA_OFFSET..13],
            &[0x92, 1, 2, 0]
        );
    }

    #[test]
    fn upload_collects_multiple_segments_without_header_or_padding() {
        let first = [10, 0, 0, 0, 0, 0x13, 0, 0x30, 0, 1, 2, 3, 4, 5, 6, 7];
        let last = [10, 0, 0, 0, 0, 0x23, 0, 0x30, 0x19, 8, 9, 10, 0, 0, 0, 0];
        let mut result = [0; 10];
        let mut total = 0;
        for frame in [first, last] {
            let headers = SdoSegmented::unpack_from_slice(&frame).unwrap();
            append_upload_segment(
                &mut result,
                &mut total,
                &headers,
                &frame[SdoSegmented::RESPONSE_DATA_OFFSET..],
            )
            .unwrap();
        }
        assert_eq!(total, 10);
        assert_eq!(result, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn emergency_during_sdo_is_queued_and_the_response_continues() {
        let device = SubDevice::default();
        let emergency = [10, 0, 0, 0, 0, 3, 0, 0x10, 0x10, 0x32, 4, 1, 2, 3, 4, 5];
        let response = [
            10, 0, 0, 0, 0, 0x13, 0, 0x30, 0x43, 0, 0x10, 0, 0x92, 1, 2, 0,
        ];
        assert!(!route_sdo_response(&device, &emergency).unwrap());
        assert!(route_sdo_response(&device, &response).unwrap());
        let queued = device.take_unsolicited_mailbox().unwrap();
        assert_eq!(Emergency::from_mailbox(&queued).unwrap().error_code, 0x3210);
        assert!(device.take_unsolicited_mailbox().is_none());
    }

    #[test]
    fn unsolicited_queue_is_bounded_and_fifo() {
        let device = SubDevice::default();
        let mut emergency = [10, 0, 0, 0, 0, 3, 0, 0x10, 1, 0, 4, 1, 2, 3, 4, 5];
        save_unsolicited(&device, &emergency).unwrap();
        emergency[8] = 2;
        save_unsolicited(&device, &emergency).unwrap();
        emergency[8] = 3;
        assert_eq!(
            save_unsolicited(&device, &emergency),
            Err(Error::Capacity(Item::UnsolicitedMailbox))
        );
        for code in [1, 2] {
            let frame = device.take_unsolicited_mailbox().unwrap();
            assert_eq!(Emergency::from_mailbox(&frame).unwrap().error_code, code);
        }
    }
}

pub struct Coe<'maindevice, S> {
    subdevice: &'maindevice SubDeviceRef<'maindevice, S>,
}

impl<'maindevice, S> Coe<'maindevice, S>
where
    S: Deref<Target = SubDevice>,
{
    pub fn new(subdevice: &'maindevice SubDeviceRef<'maindevice, S>) -> Self {
        Self { subdevice }
    }

    fn check_unsolicited_capacity(&self) -> Result<(), Error> {
        if self.subdevice.unsolicited_mailboxes.read().is_full() {
            return Err(Error::Capacity(Item::UnsolicitedMailbox));
        }
        Ok(())
    }

    // Reading the first eight bytes does not acknowledge an ESC mailbox; reading
    // through its last byte does. Only large mailboxes need this extra check.
    async fn check_message_size(&self, mailbox: &Mailbox, allow_sdo: bool) -> Result<(), Error> {
        if usize::from(mailbox.len) <= crate::subdevice::MAX_UNSOLICITED_MAILBOX_LEN {
            return Ok(());
        }
        let header = self
            .subdevice
            .read(mailbox.address)
            .receive_slice(self.subdevice.maindevice, 8)
            .await?;
        let length = usize::from(u16::from_le_bytes([header[0], header[1]])) + 6;
        let sdo = header[5] & 0x0f == 3 && header[7] >> 4 == 3;
        if length > crate::subdevice::MAX_UNSOLICITED_MAILBOX_LEN && !(allow_sdo && sdo) {
            return Err(Error::Capacity(Item::UnsolicitedMailbox));
        }
        Ok(())
    }

    /// Save a waiting message without sending a request. Returns whether one was read.
    pub(crate) async fn poll_unsolicited(&self) -> Result<bool, Error> {
        let mailbox = self
            .subdevice
            .config
            .mailbox
            .read
            .ok_or(Error::Mailbox(MailboxError::NoWriteMailbox))?;
        let status = self
            .subdevice
            .read(RegisterAddress::sync_manager_status(mailbox.sync_manager))
            .receive::<crate::sync_manager_channel::Status>(self.subdevice.maindevice)
            .await?;
        if !status.mailbox_full {
            return Ok(false);
        }
        self.check_unsolicited_capacity()?;
        self.check_message_size(&mailbox, false).await?;
        let response = self
            .subdevice
            .read(mailbox.address)
            .receive_slice(self.subdevice.maindevice, mailbox.len)
            .await?;
        save_unsolicited(self.subdevice, &response)?;
        Ok(true)
    }

    pub(crate) async fn read_pending_into(
        &self,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let mailbox = self
            .subdevice
            .config
            .mailbox
            .read
            .ok_or(Error::Mailbox(MailboxError::NoWriteMailbox))?;
        let status = self
            .subdevice
            .read(RegisterAddress::sync_manager_status(mailbox.sync_manager))
            .receive::<crate::sync_manager_channel::Status>(self.subdevice.maindevice)
            .await?;
        if !status.mailbox_full {
            return Ok(None);
        }
        // Inspect the header without acknowledging the mailbox, so an undersized
        // destination leaves the message available for a subsequent attempt.
        let header = self
            .subdevice
            .read(mailbox.address)
            .receive_slice(self.subdevice.maindevice, 6)
            .await?;
        let length = usize::from(u16::from_le_bytes([header[0], header[1]])) + 6;
        if length > output.len() || length > usize::from(mailbox.len) {
            return Err(Error::Capacity(Item::UnsolicitedMailbox));
        }
        let response = self
            .subdevice
            .read(mailbox.address)
            .receive_slice(self.subdevice.maindevice, mailbox.len)
            .await?;
        output[..length].copy_from_slice(&response[..length]);
        Ok(Some(length))
    }

    /// Get CoE read/write mailboxes, waiting for them to be ready to read/write.
    async fn wait_for_mailboxes(&self) -> Result<(Mailbox, Mailbox), Error> {
        let write_mailbox = self
            .subdevice
            .config
            .mailbox
            .write
            .ok_or(Error::Mailbox(MailboxError::NoReadMailbox))?;
        let read_mailbox = self
            .subdevice
            .config
            .mailbox
            .read
            .ok_or(Error::Mailbox(MailboxError::NoWriteMailbox))?;

        let mailbox_read_sm_status =
            RegisterAddress::sync_manager_status(read_mailbox.sync_manager);
        let mailbox_write_sm_status =
            RegisterAddress::sync_manager_status(write_mailbox.sync_manager);

        // Preserve messages already waiting before starting a new request.
        for i in 0..10 {
            let sm_status = self
                .subdevice
                .read(mailbox_read_sm_status)
                .receive::<crate::sync_manager_channel::Status>(self.subdevice.maindevice)
                .await?;

            if sm_status.mailbox_full {
                fmt::debug!(
                    "SubDevice {:#06x} OUT mailbox not empty (status {:?}). Saving.",
                    self.subdevice.configured_address(),
                    sm_status
                );

                self.check_unsolicited_capacity()?;
                self.check_message_size(&read_mailbox, false).await?;
                let response = self
                    .subdevice
                    .read(read_mailbox.address)
                    .ignore_wkc()
                    .receive_slice(self.subdevice.maindevice, read_mailbox.len)
                    .await?;
                save_unsolicited(self.subdevice, &response)?;
            } else {
                break;
            }

            // Don't delay on first iteration
            if i > 0 {
                self.subdevice.maindevice.timeouts.loop_tick().await;
            }

            if i > 1 {
                fmt::debug!("--> Retrying clear");
            }
        }

        // Wait for SubDevice IN mailbox to be available to receive data from master
        async {
            loop {
                let sm_status = self
                    .subdevice
                    .read(mailbox_write_sm_status)
                    .receive::<crate::sync_manager_channel::Status>(self.subdevice.maindevice)
                    .await?;

                if !sm_status.mailbox_full {
                    break Ok(());
                }

                self.subdevice.maindevice.timeouts.loop_tick().await;
            }
        }
        .timeout(self.subdevice.maindevice.timeouts.mailbox_echo())
        .await
        .inspect_err(|&e| {
            fmt::error!(
                "Mailbox IN ready error for SubDevice {:#06x}: {}",
                self.subdevice.configured_address(),
                e
            );
        })?;

        Ok((read_mailbox, write_mailbox))
    }

    /// Wait for a mailbox response
    async fn wait_for_mailbox_response(
        &self,
        read_mailbox: &Mailbox,
        check_unsolicited: bool,
    ) -> Result<ReceivedPdu, Error> {
        let mailbox_read_sm = RegisterAddress::sync_manager_status(read_mailbox.sync_manager);

        // Wait for SubDevice OUT mailbox to be ready
        async {
            loop {
                let sm_status = self
                    .subdevice
                    .read(mailbox_read_sm)
                    .receive::<crate::sync_manager_channel::Status>(self.subdevice.maindevice)
                    .await?;

                if sm_status.mailbox_full {
                    break Ok(());
                }

                self.subdevice.maindevice.timeouts.loop_tick().await;
            }
        }
        .timeout(self.subdevice.maindevice.timeouts.mailbox_response())
        .await
        .inspect_err(|&e| {
            fmt::error!(
                "Response mailbox IN error for SubDevice {:#06x}: {}",
                self.subdevice.configured_address(),
                e
            );
        })?;

        if check_unsolicited {
            self.check_message_size(read_mailbox, true).await?;
        }

        // Read acknowledgement from SubDevice OUT mailbox
        let response = self
            .subdevice
            .read(read_mailbox.address)
            .receive_slice(self.subdevice.maindevice, read_mailbox.len)
            .await?;

        // TODO: Retries. Refer to SOEM's `ecx_mbxreceive` for inspiration

        Ok(response)
    }

    /// Send a mailbox request, wait for response mailbox to be ready, read response from mailbox
    /// and return as a slice.
    async fn mailbox_write_read<R>(
        &'maindevice self,
        request: R,
    ) -> Result<(R, ReceivedPdu<'maindevice>), Error>
    where
        R: CoeServiceRequest + Debug,
    {
        let (read_mailbox, write_mailbox) = self.wait_for_mailboxes().await.inspect_err(|err| {
            fmt::error!(
                "{} {} {}",
                self.subdevice.configured_address(),
                self.subdevice.name(),
                err
            )
        })?;

        // Send data to SubDevice IN mailbox
        self.subdevice
            .write(write_mailbox.address)
            .with_len(write_mailbox.len)
            .send(self.subdevice.maindevice, &request.pack().as_ref())
            .await?;

        // The response deadline covers all interleaved unsolicited messages, not each
        // individual mailbox read.
        let mut response = async {
            loop {
                self.check_unsolicited_capacity()?;
                let response = self.wait_for_mailbox_response(&read_mailbox, true).await?;
                if route_sdo_response(self.subdevice, &response)? {
                    break Ok(response);
                }
            }
        }
        .timeout(self.subdevice.maindevice.timeouts.mailbox_response())
        .await?;

        /// A super generalised version of the various header shapes for responses, extracting only
        /// what we need in this method.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireRead)]
        #[wire(bytes = 12)]
        struct HeadersRaw {
            #[wire(bytes = 6)]
            header: MailboxHeader,

            #[wire(bytes = 2)]
            coe_header: CoeHeader,

            #[wire(pre_skip = 5, bits = 3)]
            command: CoeCommand,

            // 9 bytes up to here

            // SAFETY: These fields will be garbage (but not invalid) if the response is NOT an
            // abort transfer request. Use with caution!
            #[wire(bytes = 2)]
            address: u16,
            #[wire(bytes = 1)]
            sub_index: u8,
        }

        let headers = HeadersRaw::unpack_from_slice(&response)?;

        if headers.command == CoeCommand::Abort {
            // ETG 1000.6 §5.6.2.7.1 Table 40
            response.trim_front(HeadersRaw::PACKED_LEN);
            let code = CoeAbortCode::unpack_from_slice(&response)?;

            fmt::error!(
                "Mailbox error for SubDevice {:#06x} (supports complete access: {}): {}",
                self.subdevice.configured_address(),
                self.subdevice.config.mailbox.complete_access,
                code
            );

            Err(Error::Mailbox(MailboxError::Aborted {
                code,
                address: headers.address,
                sub_index: headers.sub_index,
            }))
        }
        // Validate that the mailbox response is to the request we just sent
        else if headers.header.mailbox_type != MailboxType::Coe
            || !request.validate_response(headers.address, headers.sub_index)
        {
            fmt::error!(
                "Invalid SDO response. Type: {:?} (expected {:?}), index {}, subindex {}",
                headers.header.mailbox_type,
                MailboxType::Coe,
                headers.address,
                headers.sub_index,
            );

            Err(Error::Mailbox(MailboxError::SdoResponseInvalid {
                address: headers.address,
                sub_index: headers.sub_index,
            }))
        } else {
            let headers = R::unpack_from_slice(&response)?;

            response.trim_front(R::RESPONSE_DATA_OFFSET);

            Ok((headers, response))
        }
    }

    /// Handle submitting to mailboxes for the SDO Information service.
    ///
    /// If the subdevice doesn't have the necessary mailboxes, this will return `Ok(None)`.
    ///
    /// Per ETG.1000.5 §6.1.4.1.3.4, this means sending one request and then awaiting many
    /// responses.
    // TODO: make this generic w.r.t. SDO Info header type.
    async fn send_sdo_info_service(
        &self,
        request: coe::services::ObjectDescriptionListRequest,
    ) -> Result<Option<heapless::Vec<u8, { u16::MAX as usize * 2 }>>, Error> {
        let (read_mailbox, write_mailbox) = match self.wait_for_mailboxes().await {
            Ok((read, write)) => Ok((read, write)),
            Err(Error::Mailbox(MailboxError::NoReadMailbox | MailboxError::NoWriteMailbox)) => {
                return Ok(None);
            }
            Err(err) => Err(err),
        }?;

        // Send data to SubDevice IN mailbox
        self.subdevice
            .write(write_mailbox.address)
            .with_len(write_mailbox.len)
            .send(self.subdevice.maindevice, &request.pack().as_ref())
            .await?;

        const COE_HEADER_AND_LIST_TYPE_SIZE: usize = 8;

        let mut consumed_list_type = false;
        // The biggest SDO Info request is listing all the available objects,
        // which is u16::MAX * 2 = 0x1fffe bytes big (ETG.1000.6 §5.6.3.3,
        // CiA 301 §7.4.1).
        let mut buf = heapless::Vec::<u8, 0x1fffe>::new();
        loop {
            let mut response = self.wait_for_mailbox_response(&read_mailbox, false).await?;
            let headers = ObjectDescriptionListResponse::unpack_from_slice(&response)?;
            if headers.sdo_info_header.op_code == SdoInfoOpCode::GetObjectDescriptionListResponse {
                let length = headers.mailbox.length as usize - COE_HEADER_AND_LIST_TYPE_SIZE;
                fmt::trace!(
                    "CoE Info, {} fragments left",
                    headers.sdo_info_header.fragments_left
                );
                response.trim_front(ObjectDescriptionListResponse::PACKED_LEN);
                if !consumed_list_type {
                    response.trim_front(2); // skip over the list type
                    consumed_list_type = true;
                }
                buf.extend_from_slice(&response[..length])
                    .map_err(|_| Error::Internal)?;
                if !headers.sdo_info_header.incomplete {
                    break;
                }
            }
        }
        Ok(Some(buf))
    }

    /// Write a value to the given SDO index (address) and sub-index.
    ///
    /// Note that this method currently only supports expedited SDO downloads (4 bytes maximum).
    pub async fn sdo_write<T>(
        &self,
        index: u16,
        sub_index: impl Into<SubIndex>,
        value: T,
    ) -> Result<(), Error>
    where
        T: EtherCrabWireWrite,
    {
        let sub_index = sub_index.into();

        let counter = self.subdevice.mailbox_counter();

        if value.packed_len() > 4 {
            fmt::error!("Only 4 byte SDO writes or smaller are supported currently.");

            // TODO: Normal SDO download. Only expedited requests for now
            return Err(Error::Internal);
        }

        let mut buf = [0u8; 4];

        value.pack_to_slice(&mut buf)?;

        let request =
            SdoExpedited::download(counter, index, sub_index, buf, value.packed_len() as u8);

        fmt::trace!("CoE download");

        let (_response, _data) = self.mailbox_write_read(request).await?;

        // TODO: Validate reply?

        Ok(())
    }

    /// Write multiple sub-indices of the given SDO.
    ///
    /// This is NOT a complete access write. This method is provided as sugar over individual calls
    /// to [`sdo_write`](SubDeviceRef::sdo_write) and handles setting the SDO length and sub-index
    /// automatically.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use ethercrab::{
    /// #     error::Error, MainDevice, MainDeviceConfig, PduStorage, Timeouts, std::ethercat_now
    /// # };
    /// # static PDU_STORAGE: PduStorage<8, 32> = PduStorage::new();
    /// # let (_tx, _rx, pdu_loop) = PDU_STORAGE.try_split().expect("can only split once");
    /// # let maindevice = MainDevice::new(pdu_loop, Timeouts::default(), MainDeviceConfig::default());
    /// # async {
    /// # let mut group = maindevice
    /// #     .init_single_group::<8, 8>(ethercat_now)
    /// #     .await
    /// #     .expect("Init");
    /// let subdevice = group.subdevice(&maindevice, 0).expect("No subdevice!");
    ///
    /// // This is equivalent to...
    /// subdevice.sdo_write_array(0x1c13, &[
    ///     0x1a00u16,
    ///     0x1a02,
    ///     0x1a04,
    ///     0x1a06,
    /// ]).await?;
    ///
    /// // ... this
    /// // subdevice.sdo_write(0x1c13, 0, 0u8).await?;
    /// // subdevice.sdo_write(0x1c13, 1, 0x1a00u16).await?;
    /// // subdevice.sdo_write(0x1c13, 2, 0x1a02u16).await?;
    /// // subdevice.sdo_write(0x1c13, 3, 0x1a04u16).await?;
    /// // subdevice.sdo_write(0x1c13, 4, 0x1a06u16).await?;
    /// // subdevice.sdo_write(0x1c13, 0, 4u8).await?;
    /// # Ok::<(), ethercrab::error::Error>(())
    /// # };
    /// ```
    pub async fn sdo_write_array<T>(&self, index: u16, values: impl AsRef<[T]>) -> Result<(), Error>
    where
        T: EtherCrabWireWrite,
    {
        let values = values.as_ref();

        self.sdo_write(index, 0, 0u8).await?;

        for (i, value) in values.iter().enumerate() {
            // Subindices start from 1
            let i = i + 1;

            self.sdo_write(index, i as u8, value).await?;
        }

        self.sdo_write(index, 0, values.len() as u8).await?;

        Ok(())
    }

    /// Read all sub-indices of the given SDO.
    ///
    /// This method will return an error if the number of sub-indices in the SDO is greater than
    /// `MAX_ENTRIES.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use ethercrab::{
    /// #     error::Error, MainDevice, MainDeviceConfig, PduStorage, Timeouts, std::ethercat_now
    /// # };
    /// # static PDU_STORAGE: PduStorage<8, 32> = PduStorage::new();
    /// # let (_tx, _rx, pdu_loop) = PDU_STORAGE.try_split().expect("can only split once");
    /// # let maindevice = MainDevice::new(pdu_loop, Timeouts::default(), MainDeviceConfig::default());
    /// # async {
    /// # let mut group = maindevice
    /// #     .init_single_group::<8, 8>(ethercat_now)
    /// #     .await
    /// #     .expect("Init");
    /// let subdevice = group.subdevice(&maindevice, 0).expect("No subdevice!");
    ///
    /// // Reading the TxPDO assignment
    /// // This is equivalent to...
    /// let values = subdevice.sdo_read_array::<u16, 3>(0x1c13).await?;
    ///
    /// // ... this
    /// // let len: u8 = subdevice.sdo_read(0x1c13, 0).await?;
    /// // let value1: u16 = subdevice.sdo_read(0x1c13, 1).await?;
    /// // let value2: u16 = subdevice.sdo_read(0x1c13, 2).await?;
    /// // let value3: u16 = subdevice.sdo_read(0x1c13, 3).await?;
    ///
    /// # Ok::<(), ethercrab::error::Error>(())
    /// # };
    /// ```
    pub async fn sdo_read_array<T, const MAX_ENTRIES: usize>(
        &self,
        index: u16,
    ) -> Result<heapless::Vec<T, MAX_ENTRIES>, Error>
    where
        T: EtherCrabWireReadSized,
    {
        let len = self.sdo_read::<u8>(index, 0).await?;

        if usize::from(len) > MAX_ENTRIES {
            return Err(Error::Capacity(Item::SdoSubIndex));
        }

        let mut values = heapless::Vec::new();

        for i in 1..=len {
            let value = self.sdo_read::<T>(index, i).await?;
            values.push(value).map_err(|_| Error::Internal)?;
        }

        Ok(values)
    }

    pub(crate) async fn sdo_read_expedited<T>(
        &self,
        index: u16,
        sub_index: impl Into<SubIndex>,
    ) -> Result<T, Error>
    where
        T: SdoExpeditedPayload,
    {
        debug_assert!(
            T::PACKED_LEN <= 4,
            "expedited transfers are up to 4 bytes long, this T is {}",
            T::PACKED_LEN
        );

        let sub_index = sub_index.into();

        let request = SdoNormal::upload(self.subdevice.mailbox_counter(), index, sub_index);

        fmt::trace!("CoE upload {:#06x} {:?}", index, sub_index);

        let (headers, response) = self.mailbox_write_read(request).await?;
        let data: &[u8] = &response;

        // Expedited transfers where the data is 4 bytes or less long, denoted in the SDO header
        // size value.
        if headers.sdo_header.expedited_transfer {
            let data_len = 4usize.saturating_sub(usize::from(headers.sdo_header.size));

            Ok(T::unpack_from_slice(
                data.get(0..data_len).ok_or(Error::Internal)?,
            )?)
        } else {
            Err(Error::Internal)
        }
    }

    /// Read a value from an SDO (Service Data Object) from the given index (address) and sub-index.
    pub async fn sdo_read<T>(&self, index: u16, sub_index: impl Into<SubIndex>) -> Result<T, Error>
    where
        T: EtherCrabWireReadSized,
    {
        let sub_index = sub_index.into();

        let mut storage = T::buffer();
        let buf = storage.as_mut();

        let request = SdoNormal::upload(self.subdevice.mailbox_counter(), index, sub_index);

        fmt::trace!("CoE upload {:#06x} {:?}", index, sub_index);

        let (headers, response) = self.mailbox_write_read(request).await?;
        let data: &[u8] = &response;

        // Expedited transfers where the data is 4 bytes or less long, denoted in the SDO header
        // size value.
        let response_payload = if headers.sdo_header.expedited_transfer {
            let data_len = 4usize.saturating_sub(usize::from(headers.sdo_header.size));

            data.get(0..data_len).ok_or(Error::Internal)?
        }
        // Data is either a normal upload or a segmented upload
        else {
            let data_length = headers.header.length.saturating_sub(0x0a);

            let complete_size = u32::unpack_from_slice(data)?;
            let data = data.get(u32::PACKED_LEN..).ok_or(Error::Internal)?;

            // The provided buffer isn't long enough to contain all mailbox data.
            if complete_size > buf.len() as u32 {
                return Err(Error::Mailbox(MailboxError::TooLong {
                    address: headers.sdo_header.index,
                    sub_index: headers.sdo_header.sub_index,
                }));
            }

            // If it's a normal upload, the response payload is returned in the initial mailbox read
            if complete_size <= u32::from(data_length) {
                data.get(0..usize::from(data_length))
                    .ok_or(Error::Internal)?
            }
            // If it's a segmented upload, we must make subsequent requests to load all segment data
            // from the read mailbox.
            else {
                let mut toggle = false;
                let mut total_len = 0usize;

                loop {
                    let request = SdoSegmented::upload(self.subdevice.mailbox_counter(), toggle);

                    fmt::trace!("CoE upload segmented");

                    let (headers, data) = self.mailbox_write_read(request).await?;

                    append_upload_segment(buf, &mut total_len, &headers, &data)?;

                    if headers.sdo_header.is_last_segment {
                        break;
                    }

                    toggle = !toggle;
                }

                buf.get(0..total_len).ok_or(Error::Internal)?
            }
        };

        T::unpack_from_slice(response_payload).map_err(|_| {
            fmt::error!(
                "SDO expedited data decode T: {} (len {}) data {:?} (len {})",
                type_name::<T>(),
                T::PACKED_LEN,
                response_payload,
                response_payload.len()
            );

            Error::Pdu(PduError::Decode)
        })
    }

    /// List out all of the CoE objects' addresses of kind `list_type`.
    ///
    /// For devices without CoE mailboxes, this will return `Ok(None)`.
    pub async fn sdo_info_object_description_list(
        &self,
        list_type: ObjectDescriptionListQuery,
    ) -> Result<Option<heapless::Vec<u16, /* # of u16s */ { u16::MAX as usize + 1 }>>, Error> {
        let request = ObjectDescriptionListRequest::get_object_description_list(
            self.subdevice.mailbox_counter(),
            list_type,
        );
        let Some(response_payload) = self.send_sdo_info_service(request).await? else {
            return Ok(None);
        };

        // The standard recommends to sort this, but I don't think that should be imposed onto the user
        <heapless::Vec<u16, 0x1_0000>>::unpack_from_slice(&response_payload)
            .map_err(|_| {
                fmt::error!(
                    "SDO Info Get OD List (type {}) data {:?} (len {})",
                    list_type,
                    response_payload,
                    response_payload.len()
                );

                Error::Pdu(PduError::Decode)
            })
            .map(Some)
    }

    /// Count how many objects match each [`ObjectDescriptionListQuery`].
    pub async fn sdo_info_object_quantities(
        &self,
    ) -> Result<Option<ObjectDescriptionListQueryCounts>, Error> {
        let request =
            ObjectDescriptionListRequest::get_object_quantities(self.subdevice.mailbox_counter());
        let Some(response_payload) = self.send_sdo_info_service(request).await? else {
            return Ok(None);
        };

        ObjectDescriptionListQueryCounts::unpack_from_slice(&response_payload)
            .map_err(|_| {
                fmt::error!(
                    "SDO Info Get OD List (type Object Quantities) data {:?} (len {})",
                    response_payload,
                    response_payload.len()
                );

                Error::Pdu(PduError::Decode)
            })
            .map(Some)
    }
}
