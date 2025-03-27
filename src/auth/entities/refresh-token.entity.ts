import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'refreshtoken' })
export class RefreshToken {

  @PrimaryGeneratedColumn('uuid')
  refreshTokenId: string;

  @Column({ nullable: false })
  token: string;

  @Column('uuid')
  userId: string

  @Column({ nullable: true })
  expiryDate: Date;

}
