import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'user_role'})
export class UserRole{
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({nullable: false})
    userid: string;

    @Column({nullable: false})
    rolename: string;
}