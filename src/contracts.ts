export type CustodyAction = "issue" | "return" | "lost" | "replace";
export type PackageState = "accepted" | "quarantined" | "superseded";

export interface DeviceCustodyEvent {
  eventId: string;
  studyId: string;
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  action: CustodyAction;
  occurredAt: string;
  replacesSerialNumber?: string;
}

export interface UploadManifest {
  packageId: string;
  siteId: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  signature: string;
  correctsPackageId?: string;
}

export interface FrozenDataset {
  datasetId: string;
  revision: number;
  packageDecisions: Record<string, PackageState>;
  frozenAt: string;
}
