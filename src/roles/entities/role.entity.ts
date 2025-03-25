import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'role'})
export class Permission{
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({nullable: false, unique:true})
    name: string;

    @Column({nullable: false})
    permissions: string;
} 