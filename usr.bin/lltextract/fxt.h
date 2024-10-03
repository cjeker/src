#define FXT_T_METADATA		0 /* Metadata */
#define FXT_T_INIT		1 /* Initialization */
#define FXT_T_STRING		2 /* String */
#define FXT_T_THREAD		3 /* Thread */
#define FXT_T_EVENT		4 /* Event */
#define FXT_T_BLOB		5 /* Blob */
#define FXT_T_UOBJ		6 /* Userspace object */
#define FXT_T_KOBJ		7 /* Kernel object */
#define FXT_T_SCHED		8 /* Scheduling */
#define FXT_T_LBLOB		15 /* Large BLOB */

#define FXT_H_TYPE_SHIFT	0
#define FXT_H_TYPE_BITS		4
#define FXT_H_SIZE_SHIFT	4
#define FXT_H_SIZE_BITS		12

#define FXT_MAX_WORDS		(1ULL << 12)

#define FXT_RECORD(_type, _size) \
    htole64(((_type) << FXT_H_TYPE_SHIFT) | ((_size) << FXT_H_SIZE_SHIFT))

#define FXT_H_METADATA_TYPE_SHIFT	16
#define FXT_H_METADATA_TYPE_BITS	4

#define FXT_MD_RECORD(_size, _mdtype) (FXT_RECORD(FXT_T_METADATA, (_size)) | \
    ((_mdtype) << FXT_H_METADATA_TYPE_SHIFT))

#define FXT_INIT_MAGIC 0x0016547846040010
#define FXT_INIT_RECORD(_f) FXT_RECORD(FXT_T_INIT, 2), htole64(_f)

