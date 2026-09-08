export type RecordWithAudit = {
	id: string;
	testId: string;
	operatorId: string;
	timestamp: Date;
	result: string;
	confidence: number;
	imageHash: string;
	digitalSignature: string;
	auditEvents: { event: string; timestamp: Date; operator: string }[];
};
