-- DropForeignKey
ALTER TABLE "Alert" DROP CONSTRAINT "Alert_ruleId_fkey";

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "AlertRule"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
