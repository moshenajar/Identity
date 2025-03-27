import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'user'})
export class User{
    @PrimaryGeneratedColumn('uuid')
    userId: string;

    @Column({unique:true})
    email: string;

    @Column()
    password: string;
} 