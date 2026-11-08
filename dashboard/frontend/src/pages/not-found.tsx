import { Compass } from "lucide-react";
import { Link } from "react-router-dom";

import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title="That page does not exist"
      description="The link may be outdated. Use the navigation to find what you need."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/">Back to overview</Link>
        </Button>
      }
    />
  );
}
