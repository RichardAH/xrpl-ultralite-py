STLookup = {
	10003: {
		'type_name': 'Validation',
		1: {
			'field_name': 'Validation',
			'vle': False,
			'ser': False,
			'sig': False
		}
	},
	-1: {
		'type_name': 'Done'
	},
	4: {
		'type_name': 'Hash128',
		'size': 16,
		1: {
			'field_name': 'EmailHash',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	7: {
		'type_name': 'Blob',
		1: {
			'field_name': 'PublicKey',
			'vle': True,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'MessageKey',
			'vle': True,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'SigningPubKey',
			'vle': True,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'TxnSignature',
			'vle': True,
			'ser': True,
			'sig': False
		},
		5: {
			'field_name': 'Generator',
			'vle': True,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'Signature',
			'vle': True,
			'ser': True,
			'sig': False
		},
		7: {
			'field_name': 'Domain',
			'vle': True,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'FundCode',
			'vle': True,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'RemoveCode',
			'vle': True,
			'ser': True,
			'sig': True
		},
		10: {
			'field_name': 'ExpireCode',
			'vle': True,
			'ser': True,
			'sig': True
		},
		11: {
			'field_name': 'CreateCode',
			'vle': True,
			'ser': True,
			'sig': True
		},
		12: {
			'field_name': 'MemoType',
			'vle': True,
			'ser': True,
			'sig': True
		},
		13: {
			'field_name': 'MemoData',
			'vle': True,
			'ser': True,
			'sig': True
		},
		14: {
			'field_name': 'MemoFormat',
			'vle': True,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'Fulfillment',
			'vle': True,
			'ser': True,
			'sig': True
		},
		17: {
			'field_name': 'Condition',
			'vle': True,
			'ser': True,
			'sig': True
		},
		18: {
			'field_name': 'MasterSignature',
			'vle': True,
			'ser': True,
			'sig': False
		}
	},
	8: {
		'type_name': 'AccountID',
		1: {
			'field_name': 'Account',
			'vle': True,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'Owner',
			'vle': True,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'Destination',
			'vle': True,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'Issuer',
			'vle': True,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'Authorize',
			'vle': True,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'Unauthorize',
			'vle': True,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'Target',
			'vle': True,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'RegularKey',
			'vle': True,
			'ser': True,
			'sig': True
		}
	},
	6: {
		'type_name': 'Amount',
		1: {
			'field_name': 'Amount',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'Balance',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'LimitAmount',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'TakerPays',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'TakerGets',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'LowLimit',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'HighLimit',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'Fee',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'SendMax',
			'vle': False,
			'ser': True,
			'sig': True
		},
		10: {
			'field_name': 'DeliverMin',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'MinimumOffer',
			'vle': False,
			'ser': True,
			'sig': True
		},
		17: {
			'field_name': 'RippleEscrow',
			'vle': False,
			'ser': True,
			'sig': True
		},
		18: {
			'field_name': 'DeliveredAmount',
			'vle': False,
			'ser': True,
			'sig': True
		},
		258: {
			'field_name': 'taker_gets_funded',
			'vle': False,
			'ser': False,
			'sig': False
		},
		259: {
			'field_name': 'taker_pays_funded',
			'vle': False,
			'ser': False,
			'sig': False
		}
	},
	5: {
		'type_name': 'Hash256',
		'size': 32,
		1: {
			'field_name': 'LedgerHash',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'ParentHash',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'TransactionHash',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'AccountHash',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'PreviousTxnID',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'LedgerIndex',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'WalletLocator',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'RootIndex',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'AccountTxnID',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'BookDirectory',
			'vle': False,
			'ser': True,
			'sig': True
		},
		17: {
			'field_name': 'InvoiceID',
			'vle': False,
			'ser': True,
			'sig': True
		},
		18: {
			'field_name': 'Nickname',
			'vle': False,
			'ser': True,
			'sig': True
		},
		19: {
			'field_name': 'Amendment',
			'vle': False,
			'ser': True,
			'sig': True
		},
		20: {
			'field_name': 'TicketID',
			'vle': False,
			'ser': True,
			'sig': True
		},
		21: {
			'field_name': 'Digest',
			'vle': False,
			'ser': True,
			'sig': True
		},
		257: {
			'field_name': 'hash',
			'vle': False,
			'ser': False,
			'sig': False
		},
		258: {
			'field_name': 'index',
			'vle': False,
			'ser': False,
			'sig': False
		},
		22: {
			'field_name': 'Channel',
			'vle': False,
			'ser': True,
			'sig': True
		},
		23: {
			'field_name': 'ConsensusHash',
			'vle': False,
			'ser': True,
			'sig': True
		},
		24: {
			'field_name': 'CheckID',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	16: {
		'type_name': 'UInt8',
		'size': 1,
		1: {
			'field_name': 'CloseResolution',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'Method',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'TransactionResult',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'TickSize',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	19: {
		'type_name': 'Vector256',
		'size': 32,
		1: {
			'field_name': 'Indexes',
			'vle': True,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'Hashes',
			'vle': True,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'Amendments',
			'vle': True,
			'ser': True,
			'sig': True
		}
	},
	14: {
		'type_name': 'STObject',
		1: {
			'field_name': 'ObjectEndMarker',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'TransactionMetaData',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'CreatedNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'DeletedNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'ModifiedNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'PreviousFields',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'FinalFields',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'NewFields',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'TemplateEntry',
			'vle': False,
			'ser': True,
			'sig': True
		},
		10: {
			'field_name': 'Memo',
			'vle': False,
			'ser': True,
			'sig': True
		},
		11: {
			'field_name': 'SignerEntry',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'Signer',
			'vle': False,
			'ser': True,
			'sig': True
		},
		18: {
			'field_name': 'Majority',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	-2: {
		'type_name': 'Unknown',
		0: {
			'field_name': 'Generic',
			'vle': False,
			'ser': False,
			'sig': False
		},
		-1: {
			'field_name': 'Invalid',
			'vle': False,
			'ser': False,
			'sig': False
		}
	},
	10001: {
		'type_name': 'Transaction',
		1: {
			'field_name': 'Transaction',
			'vle': False,
			'ser': False,
			'sig': False
		}
	},
	17: {
		'type_name': 'Hash160',
		'size': 20,
		1: {
			'field_name': 'TakerPaysCurrency',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'TakerPaysIssuer',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'TakerGetsCurrency',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'TakerGetsIssuer',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	18: {
		'type_name': 'PathSet',
		1: {
			'field_name': 'Paths',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	10002: {
		'type_name': 'LedgerEntry',
		1: {
			'field_name': 'LedgerEntry',
			'vle': False,
			'ser': False,
			'sig': False
		}
	},
	1: {
		'type_name': 'UInt16',
		'size': 2,
		1: {
			'field_name': 'LedgerEntryType',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'TransactionType',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'SignerWeight',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	0: {
		'type_name': 'NotPresent'
	},
	3: {
		'type_name': 'UInt64',
		'size': 8,
		1: {
			'field_name': 'IndexNext',
			'vle': False,
			'ser': True,
			'sig': True
		},
		2: {
			'field_name': 'IndexPrevious',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'BookNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'OwnerNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'BaseFee',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'ExchangeRate',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'LowNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'HighNode',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'DestinationNode',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	2: {
		'type_name': 'UInt32',
		'size': 4,
		2: {
			'field_name': 'Flags',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'SourceTag',
			'vle': False,
			'ser': True,
			'sig': True
		},
		4: {
			'field_name': 'Sequence',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'PreviousTxnLgrSeq',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'LedgerSequence',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'CloseTime',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'ParentCloseTime',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'SigningTime',
			'vle': False,
			'ser': True,
			'sig': True
		},
		10: {
			'field_name': 'Expiration',
			'vle': False,
			'ser': True,
			'sig': True
		},
		11: {
			'field_name': 'TransferRate',
			'vle': False,
			'ser': True,
			'sig': True
		},
		12: {
			'field_name': 'WalletSize',
			'vle': False,
			'ser': True,
			'sig': True
		},
		13: {
			'field_name': 'OwnerCount',
			'vle': False,
			'ser': True,
			'sig': True
		},
		14: {
			'field_name': 'DestinationTag',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'HighQualityIn',
			'vle': False,
			'ser': True,
			'sig': True
		},
		17: {
			'field_name': 'HighQualityOut',
			'vle': False,
			'ser': True,
			'sig': True
		},
		18: {
			'field_name': 'LowQualityIn',
			'vle': False,
			'ser': True,
			'sig': True
		},
		19: {
			'field_name': 'LowQualityOut',
			'vle': False,
			'ser': True,
			'sig': True
		},
		20: {
			'field_name': 'QualityIn',
			'vle': False,
			'ser': True,
			'sig': True
		},
		21: {
			'field_name': 'QualityOut',
			'vle': False,
			'ser': True,
			'sig': True
		},
		22: {
			'field_name': 'StampEscrow',
			'vle': False,
			'ser': True,
			'sig': True
		},
		23: {
			'field_name': 'BondAmount',
			'vle': False,
			'ser': True,
			'sig': True
		},
		24: {
			'field_name': 'LoadFee',
			'vle': False,
			'ser': True,
			'sig': True
		},
		25: {
			'field_name': 'OfferSequence',
			'vle': False,
			'ser': True,
			'sig': True
		},
		26: {
			'field_name': 'FirstLedgerSequence',
			'vle': False,
			'ser': True,
			'sig': True
		},
		27: {
			'field_name': 'LastLedgerSequence',
			'vle': False,
			'ser': True,
			'sig': True
		},
		28: {
			'field_name': 'TransactionIndex',
			'vle': False,
			'ser': True,
			'sig': True
		},
		29: {
			'field_name': 'OperationLimit',
			'vle': False,
			'ser': True,
			'sig': True
		},
		30: {
			'field_name': 'ReferenceFeeUnits',
			'vle': False,
			'ser': True,
			'sig': True
		},
		31: {
			'field_name': 'ReserveBase',
			'vle': False,
			'ser': True,
			'sig': True
		},
		32: {
			'field_name': 'ReserveIncrement',
			'vle': False,
			'ser': True,
			'sig': True
		},
		33: {
			'field_name': 'SetFlag',
			'vle': False,
			'ser': True,
			'sig': True
		},
		34: {
			'field_name': 'ClearFlag',
			'vle': False,
			'ser': True,
			'sig': True
		},
		35: {
			'field_name': 'SignerQuorum',
			'vle': False,
			'ser': True,
			'sig': True
		},
		36: {
			'field_name': 'CancelAfter',
			'vle': False,
			'ser': True,
			'sig': True
		},
		37: {
			'field_name': 'FinishAfter',
			'vle': False,
			'ser': True,
			'sig': True
		},
		38: {
			'field_name': 'SignerListID',
			'vle': False,
			'ser': True,
			'sig': True
		},
		39: {
			'field_name': 'SettleDelay',
			'vle': False,
			'ser': True,
			'sig': True
		}
	},
	15: {
		'type_name': 'STArray',
		1: {
			'field_name': 'ArrayEndMarker',
			'vle': False,
			'ser': True,
			'sig': True
		},
		3: {
			'field_name': 'Signers',
			'vle': False,
			'ser': True,
			'sig': False
		},
		4: {
			'field_name': 'SignerEntries',
			'vle': False,
			'ser': True,
			'sig': True
		},
		5: {
			'field_name': 'Template',
			'vle': False,
			'ser': True,
			'sig': True
		},
		6: {
			'field_name': 'Necessary',
			'vle': False,
			'ser': True,
			'sig': True
		},
		7: {
			'field_name': 'Sufficient',
			'vle': False,
			'ser': True,
			'sig': True
		},
		8: {
			'field_name': 'AffectedNodes',
			'vle': False,
			'ser': True,
			'sig': True
		},
		9: {
			'field_name': 'Memos',
			'vle': False,
			'ser': True,
			'sig': True
		},
		16: {
			'field_name': 'Majorities',
			'vle': False,
			'ser': True,
			'sig': True
		}
	}}
TXLookup = {
	-393: 'telNO_DST_PARTIAL',
	-281: 'temBAD_SRC_ACCOUNT',
	-189: 'tefPAST_SEQ',
	-96: 'terNO_ACCOUNT',
	-275: 'temREDUNDANT',
	-194: 'tefCREATED',
	-279: 'temDST_IS_SRC',
	-99: 'terRETRY',
	-276: 'temINVALID_FLAG',
	-288: 'temBAD_SEND_XRP_LIMIT',
	-94: 'terNO_LINE',
	-196: 'tefBAD_AUTH',
	-295: 'temBAD_EXPIRATION',
	-286: 'temBAD_SEND_XRP_NO_DIRECT',
	-284: 'temBAD_SEND_XRP_PATHS',
	-195: 'tefBAD_LEDGER',
	-190: 'tefNO_AUTH_REQUIRED',
	-93: 'terOWNERS',
	-91: 'terLAST',
	-90: 'terNO_RIPPLE',
	-294: 'temBAD_FEE',
	-92: 'terPRE_SEQ',
	-187: 'tefMASTER_DISABLED',
	-296: 'temBAD_CURRENCY',
	-193: 'tefDST_TAG_NEEDED',
	-282: 'temBAD_SIGNATURE',
	-199: 'tefFAILURE',
	-397: 'telBAD_PATH_COUNT',
	-280: 'temBAD_TRANSFER_RATE',
	-188: 'tefWRONG_PRIOR',
	-398: 'telBAD_DOMAIN',
	-298: 'temBAD_AMOUNT',
	-297: 'temBAD_AUTH_MASTER',
	-292: 'temBAD_LIMIT',
	-293: 'temBAD_ISSUER',
	-396: 'telBAD_PUBLIC_KEY',
	-197: 'tefBAD_ADD_AUTH',
	-291: 'temBAD_OFFER',
	-285: 'temBAD_SEND_XRP_PARTIAL',
	-278: 'temDST_NEEDED',
	-198: 'tefALREADY',
	-272: 'temUNCERTAIN',
	-399: 'telLOCAL_ERROR',
	-274: 'temREDUNDANT_SEND_MAX',
	-191: 'tefINTERNAL',
	-289: 'temBAD_PATH_LOOP',
	-192: 'tefEXCEPTION',
	-273: 'temRIPPLE_EMPTY',
	-394: 'telINSUF_FEE_P',
	-283: 'temBAD_SEQUENCE',
	-186: 'tefMAX_LEDGER',
	-98: 'terFUNDS_SPENT',
	-287: 'temBAD_SEND_XRP_MAX',
	-395: 'telFAILED_PROCESSING',
	-97: 'terINSUF_FEE_B',
	0: 'tesSUCCESS',
	-290: 'temBAD_PATH',
	-299: 'temMALFORMED',
	-271: 'temUNKNOWN',
	-277: 'temINVALID',
	-95: 'terNO_AUTH',
	-270: 'temBAD_TICK_SIZE',
	100: 'tecCLAIM',
	101: 'tecPATH_PARTIAL',
	102: 'tecUNFUNDED_ADD',
	103: 'tecUNFUNDED_OFFER',
	104: 'tecUNFUNDED_PAYMENT',
	105: 'tecFAILED_PROCESSING',
	121: 'tecDIR_FULL',
	122: 'tecINSUF_RESERVE_LINE',
	123: 'tecINSUF_RESERVE_OFFER',
	124: 'tecNO_DST',
	125: 'tecNO_DST_INSUF_XRP',
	126: 'tecNO_LINE_INSUF_RESERVE',
	127: 'tecNO_LINE_REDUNDANT',
	128: 'tecPATH_DRY',
	129: 'tecUNFUNDED',
	130: 'tecNO_ALTERNATIVE_KEY',
	131: 'tecNO_REGULAR_KEY',
	132: 'tecOWNERS',
	133: 'tecNO_ISSUER',
	134: 'tecNO_AUTH',
	135: 'tecNO_LINE',
	136: 'tecINSUFF_FEE',
	137: 'tecFROZEN',
	138: 'tecNO_TARGET',
	139: 'tecNO_PERMISSION',
	140: 'tecNO_ENTRY',
	141: 'tecINSUFFICIENT_RESERVE',
	142: 'tecNEED_MASTER_KEY',
	143: 'tecDST_TAG_NEEDED',
	144: 'tecINTERNAL',
	145: 'tecOVERSIZE',
	146: 'tecCRYPTOCONDITION_ERROR',
	147: 'tecINVARIANT_FAILED',
	148: 'tecEXPIRED',
	149: 'tecDUPLICATE'
}
LELookup = {
	-3: 'Any',
	-2: 'Child',
	-1: 'Invalid',
	97: 'AccountRoot',
	100: 'DirectoryNode',
	114: 'RippleState',
	84: 'Ticket',
	83: 'SignerList',
	111: 'Offer',
	104: 'LedgerHashes',
	102: 'Amendments',
	115: 'FeeSettings',
	117: 'Escrow',
	120: 'PayChannel',
	112: 'DepositPreauth',
	67: 'Check',
	110: 'Nickname',
	99: 'Contract',
	103: 'GeneratorMap'
}
