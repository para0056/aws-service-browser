export interface AwsAction {
    service: string;
    action: string;
    description: string;
    annotations: string[];
    conditionKeys: string[];
    resourceTypes: string[];
}

export interface ServiceIndexEntry {
    service: string;
    url: string;
}
