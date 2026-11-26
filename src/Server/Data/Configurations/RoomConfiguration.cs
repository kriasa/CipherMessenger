using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using src.Server.Data.Entities;

namespace src.Server.Data.Configurations;

public sealed class RoomConfiguration : IEntityTypeConfiguration<Room>
{
    public void Configure(EntityTypeBuilder<Room> b)
    {
        b.HasKey(x => x.Id);
        b.HasMany(x => x.Members).WithOne(m => m.Room).HasForeignKey(m => m.RoomId).OnDelete(DeleteBehavior.Cascade);
    }
}
public sealed class RoomMemberConfiguration : IEntityTypeConfiguration<RoomMember>
{
    public void Configure(EntityTypeBuilder<RoomMember> b)
    {
        b.HasKey(x => new { x.RoomId, x.UserId });
        b.HasIndex(x => x.UserId);
        b.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}
