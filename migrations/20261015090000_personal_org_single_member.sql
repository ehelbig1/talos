-- A personal organization has exactly one member, its owner (security review
-- 2026-10-14, A-1).
--
-- Every org-less resource a user creates is stamped with their personal org
-- (`set_org_id_from_personal_org`), so membership in it is access to
-- everything they own. `OrganizationService::add_member` and
-- `transfer_ownership` never read `is_personal`; they now refuse, and this
-- trigger refuses for every writer: a member row in a personal organization
-- must be its owner, and a personal organization's owner never changes.
--
-- Measured on the reference deployment: 1 personal org, 0 members other than
-- its owner — nothing existing is refused.

CREATE OR REPLACE FUNCTION refuse_personal_org_member() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM organizations o
        WHERE o.id = NEW.org_id AND o.is_personal AND o.owner_id <> NEW.user_id
    ) THEN
        RAISE EXCEPTION 'a personal organization has exactly one member, its owner'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_refuse_personal_org_member ON organization_members;
CREATE TRIGGER trg_refuse_personal_org_member
    BEFORE INSERT OR UPDATE OF org_id, user_id ON organization_members
    FOR EACH ROW EXECUTE FUNCTION refuse_personal_org_member();

CREATE OR REPLACE FUNCTION refuse_personal_org_owner_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.is_personal AND NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
        RAISE EXCEPTION 'a personal organization''s owner never changes'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_refuse_personal_org_owner_change ON organizations;
CREATE TRIGGER trg_refuse_personal_org_owner_change
    BEFORE UPDATE OF owner_id ON organizations
    FOR EACH ROW EXECUTE FUNCTION refuse_personal_org_owner_change();
