import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'refreshtoken' })
export class RefreshToken {

  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  refreshToken: string;

  @Column('uuid')
  userId: string

  @Column({ nullable: true })
  expiryDate: Date;

}
