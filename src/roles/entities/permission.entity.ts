import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { Resource } from "../enums/resource.enum";
import { Action } from "../enums/action.enum";

@Entity({ name: 'permission'})
export class Permission{
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({
        nullable: false,
        type: "enum",
        enum: Resource,
        //default: Resource.products
    })
    resource: Resource;

    @Column({
        nullable: false,
        type: "enum",
        enum: Action,
    })
    actions: Action;
} 