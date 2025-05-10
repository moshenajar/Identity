import { Injectable } from "@nestjs/common";


@Injectable()
export class CalculationsHelper {
    constructor() { }

    async IsExpirationDate(date: Date): Promise<boolean | null> {
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Reset time to midnight for an accurate comparison
        return date < today;
    }

    async ExpiryDate(): Promise<Date | null> {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() - 1);
        return expiryDate;
    }
}