pub const MULTIPART_OVERHEAD_BYTES: u64 = 64 * 1024;
pub const MAX_CODE_GENERATION_ATTEMPTS: usize = 5;
pub const MAX_EXPIRATION_HOURS: u64 = 2_160;
pub const MIN_MAX_FILE_SIZE_BYTES: u64 = 1 * 1024 * 1024;
pub const MAX_MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
pub const MIN_DIRECT_LINK_TTL_MINUTES: u64 = 1;
pub const MAX_DIRECT_LINK_TTL_MINUTES: u64 = 1_440;
pub const DEFAULT_RECENT_UPLOADS_LIMIT: i64 = 10;
pub const CODE_SEGMENT_LENGTH: usize = 4;
pub const CODE_TOTAL_LENGTH: usize = CODE_SEGMENT_LENGTH * 2;
pub const MAX_PASTE_SIZE_BYTES: u64 = 512 * 1024;
pub const CODE_ALPHABET: [char; 31] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M',
    'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
