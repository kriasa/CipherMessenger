using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using src.Server.Data.Entities;

namespace src.Server.Data.Configurations;

public sealed class ContactLinkConfiguration : IEntityTypeConfiguration<ContactLink>
{
    public void Configure(EntityTypeBuilder<ContactLink> b)
    {
        b.HasKey(x => x.Id);
        b.HasIndex(x => new { x.UserAId, x.UserBId }).IsUnique();
        b.HasIndex(x => x.UserBId);
        b.HasOne(x => x.UserA).WithMany().HasForeignKey(x => x.UserAId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne(x => x.UserB).WithMany().HasForeignKey(x => x.UserBId).OnDelete(DeleteBehavior.Cascade);
    }
}
